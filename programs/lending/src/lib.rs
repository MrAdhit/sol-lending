use anchor_lang::prelude::*;
use anchor_spl::{associated_token::AssociatedToken, token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked}};
use pyth_solana_receiver_sdk::price_update::{PriceUpdateV2, get_feed_id_from_hex};

declare_id!("FH6hQS3SU8JG4xBVxNR5988AvCzjgDy9SLncYtQ4pjG7");

#[constant]
// https://pyth.network/developers/price-feed-ids#solana-stable
pub const SOL_USD_FEED_ID: &str = "0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d";
pub const USDC_USD_FEED_ID: &str = "0xeaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a";
pub const MAXIMUM_AGE: u64 = 100; // allow price feed 100 sec old, to avoid stale price feed errors

#[program]
pub mod lending {

    use super::*;
    
    pub fn init_bank(ctx: Context<InitBank>, liquidation_threshold: u64, max_ltv: u64) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        
        bank.mint_address = ctx.accounts.mint.key();
        bank.authority = ctx.accounts.signer.key();
        bank.liquidation_threshold = liquidation_threshold;
        bank.max_ltv = max_ltv;

        Ok(())
    }
    
    pub fn init_user(ctx: Context<InitUser>, usdc_address: Pubkey) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        
        user.owner = ctx.accounts.signer.key();
        user.usdc_address = usdc_address;
        user.last_updated = Clock::get()?.unix_timestamp;

        Ok(())
    }
    
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let transfer_cpi_accounts = TransferChecked {
            from: ctx.accounts.user_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.bank_token_account.to_account_info(),
            authority: ctx.accounts.signer.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, transfer_cpi_accounts);
        let decimals = ctx.accounts.mint.decimals;
        
        token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
        
        let bank = &mut ctx.accounts.bank;
        
        if bank.total_deposits == 0 {
            bank.total_deposits = amount;
            bank.total_deposit_shares = amount;
        }
        
        let deposit_ratio = amount.checked_div(bank.total_deposits).unwrap();
        let users_shares = bank.total_deposit_shares.checked_mul(deposit_ratio).unwrap();
        
        let user = &mut ctx.accounts.user_account;
        
        match ctx.accounts.mint.to_account_info().key() {
            key if key == user.usdc_address => {
                user.deposited_usdc += amount;
                user.deposited_usdc_shares += users_shares;
            }
            _ => {
                user.deposited_sol += amount;
                user.deposited_sol_shares += users_shares;
            }
        }
        
        bank.total_deposits += amount;
        bank.total_deposit_shares += users_shares;
        
        user.last_updated = Clock::get()?.unix_timestamp;

        Ok(())
    }
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        
        let deposited_value = if ctx.accounts.mint.to_account_info().key() == user.usdc_address {
            user.deposited_usdc
        } else {
            user.deposited_sol
        };
        
        if amount > deposited_value {
            return Err(ErrorCode::InsufficientFunds.into());
        }
        
        let transfer_cpi_accounts = TransferChecked {
            from: ctx.accounts.bank_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.bank_token_account.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"treasury",
            mint_key.as_ref(),
            &[ ctx.bumps.bank_token_account ],
        ]];

        let cpi_ctx = CpiContext::new(cpi_program, transfer_cpi_accounts).with_signer(signer_seeds);
        let decimals = ctx.accounts.mint.decimals;
        
        token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
        
        let bank = &mut ctx.accounts.bank;
        let shares_to_remove = (amount as f64 / bank.total_deposits as f64) * bank.total_deposit_shares as f64;
        
        let user = &mut ctx.accounts.user_account;
        
        if ctx.accounts.mint.to_account_info().key() == user.usdc_address {
            user.deposited_usdc -= shares_to_remove as u64;
        } else {
            user.deposited_sol -= shares_to_remove as u64;
        }
        
        bank.total_deposits -= amount;
        bank.total_deposit_shares -= shares_to_remove as u64;

        Ok(())
    }
    
    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        let user = &mut ctx.accounts.user_account;
        
        let price_update = &mut ctx.accounts.price_update;

        let total_collateral = if ctx.accounts.mint.to_account_info().key() == user.usdc_address {
            let sol_feed_id = get_feed_id_from_hex(SOL_USD_FEED_ID)?;
            let sol_price = price_update.get_price_no_older_than(&Clock::get()?, MAXIMUM_AGE, &sol_feed_id)?;
            let accrued_interest = calculate_accrued_interest(user.deposited_sol, bank.interest_rate, user.last_updated)?;
            
            sol_price.price as u64 * (user.deposited_sol + accrued_interest)
        } else {
            let usdc_feed_id = get_feed_id_from_hex(USDC_USD_FEED_ID)?;
            let usdc_price = price_update.get_price_no_older_than(&Clock::get()?, MAXIMUM_AGE, &usdc_feed_id)?;
            
            usdc_price.price as u64 * user.deposited_usdc
        };
        
        let borrowable_amount = total_collateral as u64 * bank.liquidation_threshold;
        
        if borrowable_amount < amount {
            return Err(ErrorCode::OverBorrowableAmount.into());
        }
        
        let transfer_cpi_accounts = TransferChecked {
            from: ctx.accounts.bank_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.bank_token_account.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"treasury",
            mint_key.as_ref(),
            &[ ctx.bumps.bank_token_account ],
        ]];

        let cpi_ctx = CpiContext::new(cpi_program, transfer_cpi_accounts).with_signer(signer_seeds);
        let decimals = ctx.accounts.mint.decimals;
        
        token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
        
        if bank.total_borrowed == 0 {
            bank.total_borrowed = amount;
            bank.total_borrowed_shares = amount;
        }
        
        let borrow_ratio = amount.checked_div(bank.total_borrowed).unwrap();
        let users_shares = bank.total_borrowed_shares.checked_mul(borrow_ratio).unwrap();
        
        bank.total_borrowed += amount;
        bank.total_borrowed_shares += users_shares;
        
        if ctx.accounts.mint.to_account_info().key() == user.usdc_address {
            user.borrowed_usdc += amount;
            user.deposited_usdc_shares += users_shares;
        } else {
            user.borrowed_sol += amount;
            user.deposited_sol_shares += users_shares;
        }

        Ok(())
    }
    
    pub fn repay(ctx: Context<Repay>, amount: u64) -> Result<()> {
        let user = &mut ctx.accounts.user_account;
        
        let borrowed_asset = if ctx.accounts.mint.to_account_info().key() == user.usdc_address {
            user.borrowed_usdc
        } else {
            user.borrowed_sol
        };
        
        if amount > borrowed_asset {
            return Err(ErrorCode::OverRepay.into());
        }
        
        let transfer_cpi_accounts = TransferChecked {
            from: ctx.accounts.user_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.bank_token_account.to_account_info(),
            authority: ctx.accounts.signer.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, transfer_cpi_accounts);
        let decimals = ctx.accounts.mint.decimals;
        
        token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
        
        let bank = &mut ctx.accounts.bank;
        
        let borrowed_ratio = amount.checked_div(bank.total_borrowed).unwrap();
        let users_shares = bank.total_borrowed_shares.checked_mul(borrowed_ratio).unwrap();
        
        let user = &mut ctx.accounts.user_account;
        
        if ctx.accounts.mint.to_account_info().key() == user.usdc_address {
            user.borrowed_usdc -= amount;
            user.borrowed_usdc_shares -= users_shares;
        } else {
            user.borrowed_sol -= amount;
            user.borrowed_sol_shares -= users_shares;
        }
        
        bank.total_borrowed -= amount;
        bank.total_borrowed_shares -= users_shares;

        Ok(())
    }
    
    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        let collateral_bank = &mut ctx.accounts.collateral_bank;
        let user = &mut ctx.accounts.user_account;
        
        let price_update = &mut ctx.accounts.price_update;
        
        let sol_feed_id = get_feed_id_from_hex(SOL_USD_FEED_ID)?;
        let usdc_feed_id = get_feed_id_from_hex(USDC_USD_FEED_ID)?;
        
        let now = Clock::get()?;

        let sol_price = price_update.get_price_no_older_than(&now, MAXIMUM_AGE, &sol_feed_id)?;
        let usdc_price = price_update.get_price_no_older_than(&now, MAXIMUM_AGE, &usdc_feed_id)?;
        
        let total_collateral = (sol_price.price as u64 * user.deposited_sol) + (usdc_price.price as u64 * user.deposited_usdc);
        let total_borrowed = (sol_price.price as u64 * user.borrowed_sol) + (usdc_price.price as u64 * user.borrowed_usdc);
        
        let health_factor = (total_collateral * collateral_bank.liquidation_threshold) / total_borrowed;
        
        if health_factor >= 1 {
            return Err(ErrorCode::NotUndercollateralized.into());
        }
        
        let liquidation_amount = total_borrowed * collateral_bank.liquidation_close_factor;
        
        let transfer_to_bank = TransferChecked {
            from: ctx.accounts.liquidator_borrowed_token_account.to_account_info(),
            mint: ctx.accounts.borrowed_mint.to_account_info(),
            to: ctx.accounts.borrowed_bank_token_account.to_account_info(),
            authority: ctx.accounts.liquidator.to_account_info(),
        };
        
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx_to_bank = CpiContext::new(cpi_program.clone(), transfer_to_bank);
        let decimals = ctx.accounts.borrowed_mint.decimals;
        
        token_interface::transfer_checked(cpi_ctx_to_bank, liquidation_amount, decimals)?;
        
        let liquidation_bonus = (liquidation_amount * collateral_bank.liquidation_bonus) + liquidation_amount;
        
        let transfer_to_liquidator = TransferChecked {
            from: ctx.accounts.collateral_bank_token_account.to_account_info(),
            mint: ctx.accounts.collateral_mint.to_account_info(),
            to: ctx.accounts.liquidator_collateral_token_account.to_account_info(),
            authority: ctx.accounts.collateral_bank_token_account.to_account_info(),
        };
        
        let mint_key = ctx.accounts.collateral_mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            b"treasury",
            mint_key.as_ref(),
            &[ ctx.bumps.collateral_bank_token_account ],
        ]];
            
        let cpi_ctx_to_liquidator = CpiContext::new(cpi_program.clone(), transfer_to_liquidator).with_signer(signer_seeds);
        let collateral_decimals = ctx.accounts.collateral_mint.decimals;
        
        token_interface::transfer_checked(cpi_ctx_to_liquidator, liquidation_bonus, collateral_decimals)?;

        Ok(())
    }
}

fn calculate_accrued_interest(deposited: u64, interest_rate: u64, last_update: i64) -> Result<u64> {
    let current_time = Clock::get()?.unix_timestamp;
    let time_elapsed = current_time - last_update;
    let new_value = (deposited as f64 * std::f32::consts::E.powf(interest_rate as f32 * time_elapsed as f32) as f64) as u64;
    Ok(new_value)
}

#[derive(Accounts)]
pub struct InitBank<'a> {
    #[account(mut)]
    pub signer: Signer<'a>,
    pub mint: InterfaceAccount<'a, Mint>,
    
    #[account(
        init,
        space = 8 + Bank::INIT_SPACE,
        payer = signer,
        seeds = [ mint.key().as_ref() ],
        bump,
    )]
    pub bank: Account<'a, Bank>,
    
    #[account(
        init,
        token::mint = mint,
        token::authority = bank_token_account,
        payer = signer,
        seeds = [ b"treasury", mint.key().as_ref() ],
        bump,
    )]
    pub bank_token_account: InterfaceAccount<'a, TokenAccount>,
    
    pub token_program: Interface<'a, TokenInterface>,
    pub system_program: Program<'a, System>,
}

#[derive(Accounts)]
pub struct InitUser<'a> {
    #[account(mut)]
    pub signer: Signer<'a>,
    
    #[account(
        init,
        payer = signer,
        space = 8 + User::INIT_SPACE,
        seeds = [ signer.key().as_ref() ],
        bump,
    )]
    pub user_account: Account<'a, User>,

    pub system_program: Program<'a, System>,
}

#[derive(Accounts)]
pub struct Deposit<'a> {
    #[account(mut)]
    pub signer: Signer<'a>,
    pub mint: InterfaceAccount<'a, Mint>,
    
    #[account(
        mut,
        seeds = [ mint.key().as_ref() ],
        bump,
    )]
    pub bank: Account<'a, Bank>,
    
    #[account(
        mut,
        seeds = [ b"treasury", mint.key().as_ref() ],
        bump,
    )]
    pub bank_token_account: InterfaceAccount<'a, TokenAccount>,
    
    #[account(
        mut,
        seeds = [ signer.key().as_ref() ],
        bump,
    )]
    pub user_account: Account<'a, User>,
    
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = signer,
        associated_token::token_program = token_program,
    )]
    pub user_token_account: InterfaceAccount<'a, TokenAccount>,
    
    pub token_program: Interface<'a, TokenInterface>,
    pub associated_token_program: Program<'a, AssociatedToken>,
    pub system_program: Program<'a, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'a> {
    #[account(mut)]
    pub signer: Signer<'a>,
    pub mint: InterfaceAccount<'a, Mint>,
    
    #[account(
        mut,
        seeds = [ mint.key().as_ref() ],
        bump,
    )]
    pub bank: Account<'a, Bank>,
    
    #[account(
        mut,
        seeds = [ b"treasury", mint.key().as_ref() ],
        bump,
    )]
    pub bank_token_account: InterfaceAccount<'a, TokenAccount>,
    
    #[account(
        mut,
        seeds = [ signer.key().as_ref() ],
        bump,
    )]
    pub user_account: Account<'a, User>,
    
    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = signer,
        associated_token::token_program = token_program,
    )]
    pub user_token_account: InterfaceAccount<'a, TokenAccount>,

    pub token_program: Interface<'a, TokenInterface>,
    pub associated_token_program: Program<'a, AssociatedToken>,
    pub system_program: Program<'a, System>,
}

#[derive(Accounts)]
pub struct Borrow<'a> {
    #[account(mut)]
    pub signer: Signer<'a>,
    pub mint: InterfaceAccount<'a, Mint>,
    
    #[account(
        mut,
        seeds = [ mint.key().as_ref() ],
        bump,
    )]
    pub bank: Account<'a, Bank>,
    
    #[account(
        mut,
        seeds = [ b"treasury", mint.key().as_ref() ],
        bump,
    )]
    pub bank_token_account: InterfaceAccount<'a, TokenAccount>,
    
    #[account(
        mut,
        seeds = [ signer.key().as_ref() ],
        bump,
    )]
    pub user_account: Account<'a, User>,
    
    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = signer,
        associated_token::token_program = token_program,
    )]
    pub user_token_account: InterfaceAccount<'a, TokenAccount>,
    
    pub price_update: Account<'a, PriceUpdateV2>,

    pub token_program: Interface<'a, TokenInterface>,
    pub associated_token_program: Program<'a, AssociatedToken>,
    pub system_program: Program<'a, System>,
}

#[derive(Accounts)]
pub struct Repay<'a> {
    #[account(mut)]
    pub signer: Signer<'a>,
    pub mint: InterfaceAccount<'a, Mint>,
    
    #[account(
        mut,
        seeds = [ mint.key().as_ref() ],
        bump,
    )]
    pub bank: Account<'a, Bank>,
    
    #[account(
        mut,
        seeds = [ b"treasury", mint.key().as_ref() ],
        bump,
    )]
    pub bank_token_account: InterfaceAccount<'a, TokenAccount>,
    
    #[account(
        mut,
        seeds = [ signer.key().as_ref() ],
        bump,
    )]
    pub user_account: Account<'a, User>,
    
    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = signer,
        associated_token::token_program = token_program,
    )]
    pub user_token_account: InterfaceAccount<'a, TokenAccount>,

    pub token_program: Interface<'a, TokenInterface>,
    pub associated_token_program: Program<'a, AssociatedToken>,
    pub system_program: Program<'a, System>,
}

#[derive(Accounts)]
pub struct Liquidate<'a> {
    #[account(mut)]
    pub liquidator: Signer<'a>,
    pub price_update: Account<'a, PriceUpdateV2>,
    pub collateral_mint: InterfaceAccount<'a, Mint>,
    pub borrowed_mint: InterfaceAccount<'a, Mint>,
    
    #[account(
        mut,
        seeds = [ collateral_mint.key().as_ref() ],
        bump,
    )]
    pub collateral_bank: Account<'a, Bank>,
    
    #[account(
        mut,
        seeds = [ b"treasury", collateral_mint.key().as_ref() ],
        bump,
    )]
    pub collateral_bank_token_account: InterfaceAccount<'a, TokenAccount>,
    
    #[account(
        mut,
        seeds = [ borrowed_mint.key().as_ref() ],
        bump,
    )]
    pub borrowed_bank: Account<'a, Bank>,
    
    #[account(
        mut,
        seeds = [ b"treasury", borrowed_mint.key().as_ref() ],
        bump,
    )]
    pub borrowed_bank_token_account: InterfaceAccount<'a, TokenAccount>,
    
    #[account(
        mut,
        seeds = [ liquidator.key().as_ref() ],
        bump,
    )]
    pub user_account: Account<'a, User>,
    
    #[account(
        init_if_needed,
        payer = liquidator,
        associated_token::mint = collateral_mint,
        associated_token::authority = liquidator,
        associated_token::token_program = token_program,
    )]
    pub liquidator_collateral_token_account: InterfaceAccount<'a, TokenAccount>,
    
    #[account(
        init_if_needed,
        payer = liquidator,
        associated_token::mint = borrowed_mint,
        associated_token::authority = liquidator,
        associated_token::token_program = token_program,
    )]
    pub liquidator_borrowed_token_account: InterfaceAccount<'a, TokenAccount>,

    pub token_program: Interface<'a, TokenInterface>,
    pub associated_token_program: Program<'a, AssociatedToken>,
    pub system_program: Program<'a, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Bank {
    pub authority: Pubkey,
    pub mint_address: Pubkey,
    pub total_deposits: u64,
    pub total_deposit_shares: u64,
    pub total_borrowed: u64,
    pub total_borrowed_shares: u64,
    pub liquidation_threshold: u64,
    pub liquidation_bonus: u64,
    pub liquidation_close_factor: u64,
    pub max_ltv: u64,
    pub last_updated: i64,
    pub interest_rate: u64,
}

#[account]
#[derive(InitSpace)]
pub struct User {
    pub owner: Pubkey,
    pub deposited_sol: u64,
    pub deposited_sol_shares: u64,
    pub borrowed_sol: u64,
    pub borrowed_sol_shares: u64,
    pub deposited_usdc: u64,
    pub deposited_usdc_shares: u64,
    pub borrowed_usdc: u64,
    pub borrowed_usdc_shares: u64,
    pub usdc_address: Pubkey,
    pub health_factor: u64,
    pub last_updated: i64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Borrowed amount exceeds the maximum LTV.")]
    OverLTV,
    #[msg("Borrowed amount results in an under collateralized loan.")]
    UnderCollateralized,
    #[msg("Insufficient funds to withdraw.")]
    InsufficientFunds,
    #[msg("Attempting to repay more than borrowed.")]
    OverRepay,
    #[msg("Attempting to borrow more than allowed.")]
    OverBorrowableAmount,
    #[msg("User is not undercollateralized.")]
    NotUndercollateralized
}

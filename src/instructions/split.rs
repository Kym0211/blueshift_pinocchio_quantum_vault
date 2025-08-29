use std::mem::MaybeUninit;

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};
use solana_winternitz::signature::WinternitzSignature;

pub struct SplitVaultAccounts<'a> {
    pub vault: &'a AccountInfo,
    pub split: &'a AccountInfo,
    pub refund: &'a AccountInfo 
}

impl<'a> TryFrom<&'a [AccountInfo]> for SplitVaultAccounts<'a> {
    type Error = ProgramError;

    fn try_from(accounts: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [vault, split, refund] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys); 
        };

        Ok(Self { vault, split, refund }) 
    } 
}

pub struct SplitVaultInstructionData {
    pub signature: WinternitzSignature,
    pub amount: [u8; 8],
    pub bump: [u8; 1], 
}

impl<'a> TryFrom<&'a [u8]> for SplitVaultInstructionData {
    type Error = ProgramError;

    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        if data.len() != size_of::<SplitVaultInstructionData>() {
            return Err(ProgramError::InvalidInstructionData); 
        } 

        let mut signature_array = MaybeUninit::<[u8; 896]>::uninit();
        unsafe {
            core::ptr::copy_nonoverlapping(data[0..896].as_ptr(), signature_array.as_mut_ptr() as *mut u8, 896);
        }

        Ok(Self { 
            signature: WinternitzSignature::from(unsafe { signature_array.assume_init() }), 
            amount: data[897..905].try_into().map_err(|_| ProgramError::InvalidInstructionData)?, 
            bump: data[896..897].try_into().map_err(|_| ProgramError::InvalidInstructionData)? })
    }
}

pub struct SplitVault<'a> {
    pub accounts: SplitVaultAccounts<'a>,
    pub instruction_data: SplitVaultInstructionData,
}
 
impl<'a> TryFrom<(&'a [u8], &'a [AccountInfo])> for SplitVault<'a> {
    type Error = ProgramError;
 
    fn try_from((data, accounts): (&'a [u8], &'a [AccountInfo])) -> Result<Self, Self::Error> {
        let instruction_data = SplitVaultInstructionData::try_from(data)?;
        let accounts = SplitVaultAccounts::try_from(accounts)?;
 
        Ok(Self { accounts, instruction_data })
    }
}
 
impl<'a> SplitVault<'a> {
    pub const DISCRIMINATOR: &'a u8 = &1;
 
    pub fn process(&self) -> ProgramResult {
        let mut message = [0u8; 72];
        message[0..8].clone_from_slice(&self.instruction_data.amount);
        message[8..40].clone_from_slice(self.accounts.split.key());
        message[40..].clone_from_slice(self.accounts.refund.key());
 
        let hash = self.instruction_data.signature.recover_pubkey(&message).merklize();
 
        // Fast PDA equivalence check
        if solana_nostd_sha256::hashv(&[
            hash.as_ref(),
            self.instruction_data.bump.as_ref(),
            crate::ID.as_ref(),
            b"ProgramDerivedAddress",
        ])
        .ne(self.accounts.vault.key())
        {
            return Err(ProgramError::MissingRequiredSignature);
        }
 
        *self.accounts.split.try_borrow_mut_lamports()? += u64::from_le_bytes(self.instruction_data.amount);
        *self.accounts.refund.try_borrow_mut_lamports()? += self.accounts.vault.lamports().saturating_sub(u64::from_le_bytes(self.instruction_data.amount));
 
        self.accounts.vault.close()
    }
}
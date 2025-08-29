use std::mem::MaybeUninit;

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};
use solana_winternitz::signature::WinternitzSignature;

pub struct CloseVaultAccounts<'a> {
    pub vault: &'a AccountInfo,
    pub refund: &'a AccountInfo,
}
 
impl<'a> TryFrom<&'a [AccountInfo]> for CloseVaultAccounts<'a> {
    type Error = ProgramError;
 
    fn try_from(accounts: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [vault, refund] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };
 
        Ok(Self { vault, refund })
    }
}
 
 pub struct CloseVaultInstructionData {
    pub signature: WinternitzSignature,
    pub bump: [u8; 1],
}
 
impl<'a> TryFrom<&'a [u8]> for CloseVaultInstructionData {
    type Error = ProgramError;
 
    fn try_from(data: &'a [u8]) -> Result<Self, Self::Error> {
        if data.len() != core::mem::size_of::<CloseVaultInstructionData>() {
            return Err(ProgramError::InvalidInstructionData);
        }
 
        let mut signature_array = MaybeUninit::<[u8; 896]>::uninit();
        unsafe {
            core::ptr::copy_nonoverlapping(data[0..896].as_ptr(), signature_array.as_mut_ptr() as *mut u8, 896);
        }
        
        Ok(Self { 
            signature: WinternitzSignature::from(unsafe { signature_array.assume_init() }),
            bump: data[896..897].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
        })
    }
}

pub struct CloseVault<'a> {
    pub accounts: CloseVaultAccounts<'a>,
    pub instruction_data: CloseVaultInstructionData,
}
 
impl<'a> TryFrom<(&'a [u8], &'a [AccountInfo])> for CloseVault<'a> {
    type Error = ProgramError;
 
    fn try_from((data, accounts): (&'a [u8], &'a [AccountInfo])) -> Result<Self, Self::Error> {
        let instruction_data = CloseVaultInstructionData::try_from(data)?;
        let accounts = CloseVaultAccounts::try_from(accounts)?;
 
        Ok(Self { accounts, instruction_data })
    }
}
 
impl<'a> CloseVault<'a> {
    pub const DISCRIMINATOR: &'a u8 = &2;
 
    pub fn process(&self) -> ProgramResult {
        let hash = self.instruction_data.signature.recover_pubkey(self.accounts.refund.key()).merklize();
 
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
 
        *self.accounts.refund.try_borrow_mut_lamports()? += self.accounts.vault.lamports();
        self.accounts.vault.close()
    }
}
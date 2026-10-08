//! src/tokens/MultiBOLT.ts (+ BOLT.ts): the SimpleMultiBOLT fungible token class (Go: multibolt.go).

use std::rc::Rc;

use crate::boltlib::{build_outpoint, le32, P2PKHUnlock};
use crate::error::{err, Result};
use crate::pay2proof::{pay2proof_lock, Pay2ProofUnlock};
use crate::script::{chunk_data, hex_encode, Chunk, Script, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};
use crate::sighash::{hash160, Recipient, Signer};
use crate::simplemulti::{SimpleMultiTemplate, SmbLockArgs, SmbUnlockArgs};
use crate::spend::verify_tx;
use crate::tx::{tx_ref, Input, Output, Transaction, TxRef};
use crate::txbuild::{fee0, reparse, sign_tx};

/// `new P2PKH().lock(pkh)`.
pub fn p2pkh_lock(pkh: &[u8]) -> Script {
    Script::new(vec![
        Chunk::op(OP_DUP),
        Chunk::op(OP_HASH160),
        Chunk::push(pkh.len() as u8, pkh.to_vec()),
        Chunk::op(OP_EQUALVERIFY),
        Chunk::op(OP_CHECKSIG),
    ])
}

/// mint()'s default 16-byte balance.
pub const DEFAULT_MINT_BALANCE: [u8; 16] = [0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// merge()/split()'s optional { tx, vout, key }.
#[derive(Clone, Default)]
pub struct FundingSource {
    pub tx: Option<TxRef>,
    pub vout: Option<u32>,
    pub key: Option<Rc<dyn Signer>>,
}

/// commit/settle/transfer's optional arguments.
#[derive(Clone, Default)]
pub struct TransferOpts {
    pub force_no_change: bool,
    pub fund_override: Option<Input>,
    pub force_no_fund: bool,
    pub custom_change_script: Option<Script>,
}

/// The fungible token builder (TS class SimpleMultiBOLT extends BOLT).
#[derive(Clone)]
pub struct SimpleMultiBOLT {
    pub tx: Option<TxRef>,
    pub vout_idx: u32,
    pub prev_txs: Vec<TxRef>,
    pub pub_key: Vec<u8>,
    pub issuer_pub_key: Vec<u8>,
    pub genesis_outpoint: Vec<u8>,
    pub signer: Option<Rc<dyn Signer>>,
    pub pub_key_hash: Vec<u8>,
    pub skip_verify: bool,
    pub balance: Vec<u8>,
    pub balance_commit: Vec<u8>,
    pub output_index_n: Vec<u8>,
}

impl Default for SimpleMultiBOLT {
    fn default() -> Self {
        SimpleMultiBOLT {
            tx: None,
            vout_idx: 0,
            prev_txs: vec![],
            pub_key: vec![],
            issuer_pub_key: vec![],
            genesis_outpoint: vec![],
            signer: None,
            pub_key_hash: vec![],
            skip_verify: false,
            balance: vec![],
            balance_commit: vec![0; 16],
            output_index_n: vec![0],
        }
    }
}

fn seq() -> Option<u32> {
    Some(0xffff_ffff)
}

fn input(src: &TxRef, vout: u32, template: Rc<dyn crate::boltlib::UnlockTemplate>) -> Input {
    Input { source_transaction: Some(src.clone()), source_output_index: vout, template: Some(template), sequence: seq(), ..Default::default() }
}

fn change_out(lock: Script) -> Output {
    Output { satoshis: None, locking_script: Some(lock), change: true }
}

fn balance_to_u128(b: &[u8]) -> u128 {
    let mut a = [0u8; 16];
    let n = b.len().min(16);
    a[..n].copy_from_slice(&b[..n]);
    u128::from_le_bytes(a)
}

/// The class's 128-bit LE helpers (wrapping at 2^128).
pub fn add_balances(a: &[u8], b: &[u8]) -> Vec<u8> {
    balance_to_u128(a).wrapping_add(balance_to_u128(b)).to_le_bytes().to_vec()
}
pub fn subtract_balances(a: &[u8], b: &[u8]) -> Vec<u8> {
    balance_to_u128(a).wrapping_sub(balance_to_u128(b)).to_le_bytes().to_vec()
}

impl SimpleMultiBOLT {
    /// `new SimpleMultiBOLT()`.
    pub fn new() -> Self {
        Self::default()
    }

    fn signer(&self) -> Result<Rc<dyn Signer>> {
        match &self.signer {
            Some(s) => Ok(s.clone()),
            None => err("Cannot read properties of undefined (reading 'publicKey')"),
        }
    }

    fn cur_tx(&self) -> Result<TxRef> {
        match &self.tx {
            Some(t) => Ok(t.clone()),
            None => err("Cannot read properties of undefined (reading 'outputs')"),
        }
    }

    fn verify_and_log(&self, tx: &TxRef, tx_type: &str) -> Result<()> {
        if self.skip_verify {
            return Ok(());
        }
        let n = tx.borrow().inputs.len();
        for k in 0..n {
            let src = tx.borrow().inputs[k].source_transaction.clone();
            if tx.borrow().inputs[k].source_txid.is_none() {
                if let Some(s) = src {
                    let id = s.borrow().id()?;
                    tx.borrow_mut().inputs[k].source_txid = Some(id);
                }
            }
        }
        let res = verify_tx(&mut tx.borrow_mut(), true)?;
        if !res.valid {
            return err(format!("{tx_type} tx not valid [bsv]"));
        }
        Ok(())
    }

    async fn finish(&self, tx: Transaction, force_no_change: bool) -> Result<TxRef> {
        let tx = tx_ref(tx);
        if !force_no_change {
            fee0(&mut tx.borrow_mut())?;
        }
        sign_tx(&tx).await?;
        let clean = reparse(&tx.borrow())?;
        Ok(tx_ref(clean))
    }

    /// `mint(owner, sourceTransaction, _mintData = "", balance = DEFAULT_MINT_BALANCE)` (balance None = default).
    pub async fn mint(&mut self, owner: Rc<dyn Signer>, source: &TxRef, balance: Option<Vec<u8>>) -> Result<()> {
        let balance = balance.unwrap_or(DEFAULT_MINT_BALANCE.to_vec());
        let pub_key = owner.public_key();
        let pkh_hex = hex_encode(&hash160(&pub_key));
        let mut idx = None;
        for (k, o) in source.borrow().outputs.iter().enumerate() {
            let l = o.locking_script.clone().unwrap_or_default();
            if l.chunks().len() <= 2 {
                return err("Cannot read properties of undefined (reading 'data')");
            }
            if hex_encode(&chunk_data(&l, 2)) == pkh_hex {
                idx = Some(k as u32);
                break;
            }
        }
        let idx = match idx {
            None => return err("Input 0 sourceOutputIndex must be a uint32"),
            Some(i) => i,
        };
        self.pub_key_hash = hash160(&pub_key);
        self.balance = balance;
        let token_lock = SimpleMultiTemplate::lock(
            &pub_key,
            &self.prev_txs,
            &SmbLockArgs {
                balance: Some(self.balance.clone()),
                balance_commit: Some(vec![0; 16]),
                pub_key_hash_commit: Some(vec![0; 20]),
                pub_key_hash_commit2: Some(vec![0; 20]),
                other_grandparent_outpoint: Some(vec![0; 36]),
                txo_type: Some(vec![0x20]),
                output_index_n: Some(vec![0x00]),
                prev_vout_idx: 0,
            },
        )?;
        let mint = tx_ref(Transaction {
            version: 2,
            inputs: vec![input(source, idx, Rc::new(P2PKHUnlock(owner.clone())))],
            outputs: vec![Output::new(1, token_lock), change_out(p2pkh_lock(&self.pub_key_hash))],
            ..Default::default()
        });
        fee0(&mut mint.borrow_mut())?;
        sign_tx(&mint).await?;
        let res = verify_tx(&mut mint.borrow_mut(), false)?;
        if !res.valid {
            return err("Mint tx not valid");
        }
        self.genesis_outpoint = build_outpoint(&mint.borrow(), 0)?;
        self.tx = Some(mint.clone());
        self.vout_idx = 0;
        self.prev_txs.push(mint);
        self.pub_key = pub_key.clone();
        self.issuer_pub_key = pub_key;
        self.signer = Some(owner);
        Ok(())
    }

    fn find_proof_vout(ancestor: &TxRef, key: &Rc<dyn Signer>) -> u32 {
        let pkh = hex_encode(&hash160(&key.public_key()));
        let a = ancestor.borrow();
        for i in 1..a.outputs.len().saturating_sub(1) {
            if hex_encode(&a.outputs[i].locking_script.as_ref().map(|s| chunk_data(s, 4)).unwrap_or_default()) == pkh {
                return i as u32;
            }
        }
        1
    }

    /// `createTransferInputs(to, _misc, isCommitTx, forceNoChange, fundOverride, forceNoFund)`.
    pub fn create_transfer_inputs(&self, to: &Recipient, is_commit: bool, force_no_change: bool, fund_override: Option<Input>, force_no_fund: bool) -> Result<Vec<Input>> {
        let signer = self.signer()?;
        let has_ancestor = !is_commit && self.prev_txs.len() >= 3;
        let mut proof_vout = 1;
        if has_ancestor {
            proof_vout = Self::find_proof_vout(&self.prev_txs[self.prev_txs.len() - 3], &signer);
        }
        let cur = self.cur_tx()?;
        let token = input(
            &cur,
            self.vout_idx,
            Rc::new(SimpleMultiTemplate::unlock(
                signer.clone(),
                &to.pub_key(),
                self.prev_txs.clone(),
                SmbUnlockArgs {
                    force_no_change,
                    force_no_fund,
                    next_balance_commit: Some(vec![]),
                    next_txo_type: Some(vec![if is_commit { 0x21 } else { 0x20 }]),
                    input_index_n: Some(vec![0x00]),
                    pub_key_hash2: Some(vec![]),
                    grandparent_bolt_vout_idx: Some(if has_ancestor { le32(proof_vout) } else { vec![] }),
                    ..Default::default()
                },
            )),
        );
        let funding = match fund_override {
            Some(f) => f,
            None => {
                let vout = cur.borrow().outputs.len() as u32 - 1;
                input(&cur, vout, Rc::new(P2PKHUnlock(signer.clone())))
            }
        };
        if has_ancestor {
            let proof = input(&self.prev_txs[self.prev_txs.len() - 3], proof_vout, Rc::new(Pay2ProofUnlock::new(signer, 0, None)));
            return Ok(if force_no_fund { vec![token, proof] } else { vec![token, proof, funding] });
        }
        Ok(if force_no_fund { vec![token] } else { vec![token, funding] })
    }

    /// `createTransferOutputs(to, isCommitTx, forceNoChange, customChangeScript)`.
    pub fn create_transfer_outputs(&self, to: &Recipient, is_commit: bool, force_no_change: bool, custom: Option<Script>) -> Result<Vec<Output>> {
        let to_pkh = hash160(&to.pub_key());
        let pkh_commit = if is_commit { to_pkh.clone() } else { vec![0; 20] };
        let owner = if is_commit { self.pub_key.clone() } else { to.pub_key() };
        let lock = SimpleMultiTemplate::lock(
            &owner,
            &self.prev_txs,
            &SmbLockArgs {
                balance: Some(self.balance.clone()),
                balance_commit: Some(self.balance_commit.clone()),
                pub_key_hash_commit: Some(pkh_commit.clone()),
                pub_key_hash_commit2: Some(vec![0; 20]),
                other_grandparent_outpoint: Some(vec![0; 36]),
                txo_type: Some(vec![if is_commit { 0x21 } else { 0x20 }]),
                output_index_n: Some(vec![0x00]),
                prev_vout_idx: if is_commit { self.vout_idx as usize } else { 0 },
            },
        )?;
        let token = Output::new(1, lock);
        let proof = Output::new(1, pay2proof_lock(&pkh_commit));
        let change = change_out(custom.unwrap_or_else(|| p2pkh_lock(if is_commit { &self.pub_key_hash } else { &to_pkh })));
        Ok(match (is_commit, force_no_change) {
            (false, true) => vec![token],
            (false, false) => vec![token, change],
            (true, true) => vec![token, proof],
            (true, false) => vec![token, proof, change],
        })
    }

    /// `commit(to, miscData, forceNoChange, fundOverride, forceNoFund, customChangeScript)`.
    pub async fn commit(&mut self, to: &Recipient, o: TransferOpts) -> Result<()> {
        let inputs = self.create_transfer_inputs(to, true, o.force_no_change, o.fund_override.clone(), o.force_no_fund)?;
        let outputs = self.create_transfer_outputs(to, true, o.force_no_change, o.custom_change_script.clone())?;
        let tx = self.finish(Transaction { version: 2, inputs, outputs, ..Default::default() }, o.force_no_change).await?;
        self.tx = Some(tx.clone());
        self.verify_and_log(&tx, "COMMIT TX")?;
        self.vout_idx = 0;
        self.prev_txs.push(tx);
        Ok(())
    }

    /// `settle(to, miscData, forceNoChange, fundOverride, forceNoFund, customChangeScript)`.
    pub async fn settle(&mut self, to: &Recipient, o: TransferOpts) -> Result<()> {
        let outputs = self.create_transfer_outputs(to, false, o.force_no_change, o.custom_change_script.clone())?;
        let inputs = self.create_transfer_inputs(to, false, o.force_no_change, o.fund_override.clone(), o.force_no_fund)?;
        let tx = self.finish(Transaction { version: 2, inputs, outputs, ..Default::default() }, o.force_no_change).await?;
        self.tx = Some(tx.clone());
        self.verify_and_log(&tx, "SETTLE TX")?;
        self.prev_txs.push(tx);
        if let Some(s) = to.signer() {
            self.signer = Some(s);
        }
        self.pub_key = to.pub_key();
        self.pub_key_hash = hash160(&self.pub_key);
        Ok(())
    }

    /// `transfer(to, commitMisc, settleMisc, skipSettle, forceNoChange, fundOverride, forceNoFund, customChangeScript)`.
    pub async fn transfer(&mut self, to: &Recipient, skip_settle: bool, o: TransferOpts) -> Result<()> {
        self.commit(to, o.clone()).await?;
        if !skip_settle {
            self.settle(to, o).await?;
        }
        Ok(())
    }

    fn parent_outpoint(&self) -> Result<Vec<u8>> {
        let t = self.cur_tx()?;
        let b = t.borrow();
        match b.outputs.get(self.vout_idx as usize).and_then(|o| o.locking_script.as_ref()) {
            None => err("Cannot read properties of undefined (reading 'lockingScript')"),
            Some(l) => Ok(chunk_data(l, 8)),
        }
    }

    fn funding_of(&self, fs: &Option<FundingSource>) -> Result<(TxRef, u32, Rc<dyn Signer>)> {
        let cur = self.cur_tx()?;
        let mut tx = cur.clone();
        let mut vout = cur.borrow().outputs.len() as u32 - 1;
        let mut key = self.signer()?;
        if let Some(f) = fs {
            if let Some(t) = &f.tx {
                tx = t.clone();
            }
            if let Some(v) = f.vout {
                vout = v;
            }
            if let Some(k) = &f.key {
                key = k.clone();
            }
        }
        Ok((tx, vout, key))
    }

    /// `merge(other, toKey, fundingSource?)`: absorb other into this token.
    pub async fn merge(&mut self, other: &mut SimpleMultiBOLT, to_key: &Recipient, fs: Option<FundingSource>) -> Result<()> {
        let to_pkh = hash160(&to_key.pub_key());
        let (fund_tx, fund_vout, fund_key) = self.funding_of(&fs)?;
        let me = self.cur_tx()?;
        let ot = other.cur_tx()?;
        let this_in = input(
            &me,
            self.vout_idx,
            Rc::new(SimpleMultiTemplate::unlock(self.signer()?, &to_key.pub_key(), self.prev_txs.clone(), SmbUnlockArgs {
                next_balance_commit: Some(other.balance.clone()),
                next_txo_type: Some(vec![0x25]),
                input_index_n: Some(vec![0x00]),
                pub_key_hash2: Some(vec![]),
                grandparent_bolt_vout_idx: Some(vec![]),
                interop_bolt_vout_idx: Some(vec![]),
                interop_pub_key_hash: Some(vec![]),
                interop_outpoint: Some(build_outpoint(&ot.borrow(), other.vout_idx)?),
                interop_parent_outpoint: Some(other.parent_outpoint()?),
                ..Default::default()
            })),
        );
        let other_in = input(
            &ot,
            other.vout_idx,
            Rc::new(SimpleMultiTemplate::unlock(other.signer()?, &to_key.pub_key(), other.prev_txs.clone(), SmbUnlockArgs {
                next_balance_commit: Some(self.balance.clone()),
                next_txo_type: Some(vec![0x25]),
                input_index_n: Some(vec![0x01]),
                pub_key_hash2: Some(vec![]),
                grandparent_bolt_vout_idx: Some(vec![]),
                interop_bolt_vout_idx: Some(vec![]),
                interop_pub_key_hash: Some(hash160(&self.pub_key)),
                interop_outpoint: Some(build_outpoint(&me.borrow(), self.vout_idx)?),
                interop_parent_outpoint: Some(self.parent_outpoint()?),
                ..Default::default()
            })),
        );
        let fund_in = input(&fund_tx, fund_vout, Rc::new(P2PKHUnlock(fund_key)));
        let token = SimpleMultiTemplate::lock(&self.pub_key, &self.prev_txs, &SmbLockArgs {
            balance: Some(self.balance.clone()),
            balance_commit: Some(other.balance.clone()),
            pub_key_hash_commit: Some(to_pkh.clone()),
            pub_key_hash_commit2: Some(vec![0; 20]),
            other_grandparent_outpoint: Some(other.parent_outpoint()?),
            txo_type: Some(vec![0x25]),
            output_index_n: Some(vec![0x00]),
            prev_vout_idx: self.vout_idx as usize,
        })?;
        let commit = self
            .finish(
                Transaction {
                    version: 2,
                    inputs: vec![this_in, other_in, fund_in],
                    outputs: vec![Output::new(1, token), Output::new(1, pay2proof_lock(&to_pkh)), change_out(p2pkh_lock(&self.pub_key_hash))],
                    ..Default::default()
                },
                false,
            )
            .await?;
        self.verify_and_log(&commit, "MERGE COMMIT TX")?;
        self.prev_txs.push(commit.clone());
        other.prev_txs.push(commit.clone());

        let this_anc = self.prev_txs[self.prev_txs.len() - 3].clone();
        let other_anc = other.prev_txs[other.prev_txs.len() - 3].clone();
        let this_proof = Self::find_proof_vout(&this_anc, &self.signer()?);
        let other_proof = Self::find_proof_vout(&other_anc, &other.signer()?);
        let settle_in = input(
            &commit,
            0,
            Rc::new(SimpleMultiTemplate::unlock(self.signer()?, &to_key.pub_key(), self.prev_txs.clone(), SmbUnlockArgs {
                next_balance_commit: Some(vec![0; 16]),
                next_txo_type: Some(vec![0x24]),
                input_index_n: Some(vec![0x00]),
                pub_key_hash2: Some(vec![]),
                grandparent_bolt_vout_idx: Some(le32(this_proof)),
                interop_bolt_vout_idx: Some(le32(other_proof)),
                interop_pub_key_hash: Some(vec![]),
                interop_outpoint: Some(vec![]),
                interop_parent_outpoint: Some(vec![]),
                ancestor_tx_b_ref: Some(other_anc.clone()),
                ..Default::default()
            })),
        );
        let proof0 = input(&this_anc, this_proof, Rc::new(Pay2ProofUnlock::new(self.signer()?, 0, None)));
        let proof1 = input(&other_anc, other_proof, Rc::new(Pay2ProofUnlock::new(other.signer()?, 0, None)));
        let fund_vout = commit.borrow().outputs.len() as u32 - 1;
        let settle_fund = input(&commit, fund_vout, Rc::new(P2PKHUnlock(self.signer()?)));
        let merged = add_balances(&self.balance, &other.balance);
        let settle_token = SimpleMultiTemplate::lock(&to_key.pub_key(), &self.prev_txs, &SmbLockArgs {
            balance: Some(merged.clone()),
            balance_commit: Some(vec![0; 16]),
            pub_key_hash_commit: Some(vec![0; 20]),
            pub_key_hash_commit2: Some(vec![0; 20]),
            other_grandparent_outpoint: Some(vec![0; 36]),
            txo_type: Some(vec![0x24]),
            output_index_n: Some(vec![0x00]),
            prev_vout_idx: 0,
        })?;
        let settle = self
            .finish(
                Transaction {
                    version: 2,
                    inputs: vec![settle_in, proof0, proof1, settle_fund],
                    outputs: vec![Output::new(1, settle_token), change_out(p2pkh_lock(&hash160(&to_key.pub_key())))],
                    ..Default::default()
                },
                false,
            )
            .await?;
        self.verify_and_log(&settle, "MERGE SETTLE TX")?;
        self.tx = Some(settle.clone());
        self.vout_idx = 0;
        self.prev_txs.push(settle);
        if let Some(s) = to_key.signer() {
            self.signer = Some(s);
        }
        self.pub_key = to_key.pub_key();
        self.pub_key_hash = hash160(&self.pub_key);
        self.balance = merged;
        self.balance_commit = vec![0; 16];
        Ok(())
    }

    /// `split(toKeyA, toKeyB, splitBalanceCommit, fundingSource?)`: this becomes piece A; returns piece B.
    pub async fn split(&mut self, to_a: &Recipient, to_b: &Recipient, split_balance_commit: &[u8], fs: Option<FundingSource>) -> Result<SimpleMultiBOLT> {
        let pkh_a = hash160(&to_a.pub_key());
        let pkh_b = hash160(&to_b.pub_key());
        let (fund_tx, fund_vout, fund_key) = self.funding_of(&fs)?;
        let me = self.cur_tx()?;
        let token_in = input(
            &me,
            self.vout_idx,
            Rc::new(SimpleMultiTemplate::unlock(self.signer()?, &to_a.pub_key(), self.prev_txs.clone(), SmbUnlockArgs {
                next_balance_commit: Some(split_balance_commit.to_vec()),
                next_txo_type: Some(vec![0x23]),
                input_index_n: Some(vec![0x00]),
                pub_key_hash2: Some(pkh_b.clone()),
                ..Default::default()
            })),
        );
        let fund_in = input(&fund_tx, fund_vout, Rc::new(P2PKHUnlock(fund_key)));
        let token = SimpleMultiTemplate::lock(&self.pub_key, &self.prev_txs, &SmbLockArgs {
            balance: Some(self.balance.clone()),
            balance_commit: Some(split_balance_commit.to_vec()),
            pub_key_hash_commit: Some(pkh_a.clone()),
            pub_key_hash_commit2: Some(pkh_b.clone()),
            other_grandparent_outpoint: Some(vec![0; 36]),
            txo_type: Some(vec![0x23]),
            output_index_n: Some(vec![0x00]),
            prev_vout_idx: self.vout_idx as usize,
        })?;
        let commit = self
            .finish(
                Transaction {
                    version: 2,
                    inputs: vec![token_in, fund_in],
                    outputs: vec![
                        Output::new(1, token),
                        Output::new(1, pay2proof_lock(&pkh_a)),
                        Output::new(1, pay2proof_lock(&pkh_b)),
                        change_out(p2pkh_lock(&self.pub_key_hash)),
                    ],
                    ..Default::default()
                },
                false,
            )
            .await?;
        self.verify_and_log(&commit, "SPLIT COMMIT TX")?;
        self.prev_txs.push(commit.clone());

        let anc = self.prev_txs[self.prev_txs.len() - 3].clone();
        let anc_proof = Self::find_proof_vout(&anc, &self.signer()?);
        let settle_in = input(
            &commit,
            0,
            Rc::new(SimpleMultiTemplate::unlock(self.signer()?, &[], self.prev_txs.clone(), SmbUnlockArgs {
                next_balance_commit: Some(vec![]),
                next_txo_type: Some(vec![0x22]),
                input_index_n: Some(vec![0x00]),
                pub_key_hash2: Some(vec![]),
                grandparent_bolt_vout_idx: Some(le32(anc_proof)),
                ..Default::default()
            })),
        );
        let proof_in = input(&anc, anc_proof, Rc::new(Pay2ProofUnlock::new(self.signer()?, 0, None)));
        let fv = commit.borrow().outputs.len() as u32 - 1;
        let settle_fund = input(&commit, fv, Rc::new(P2PKHUnlock(self.signer()?)));
        let main_balance = subtract_balances(&self.balance, split_balance_commit);
        let lock_for = |pk: &[u8], bal: Vec<u8>, n: u8| {
            SimpleMultiTemplate::lock(pk, &self.prev_txs, &SmbLockArgs {
                balance: Some(bal),
                balance_commit: Some(vec![0; 16]),
                pub_key_hash_commit: Some(vec![0; 20]),
                pub_key_hash_commit2: Some(vec![0; 20]),
                other_grandparent_outpoint: Some(vec![0; 36]),
                txo_type: Some(vec![0x22]),
                output_index_n: Some(vec![n]),
                prev_vout_idx: 0,
            })
        };
        let out0 = lock_for(&to_a.pub_key(), main_balance.clone(), 0)?;
        let out1 = lock_for(&to_b.pub_key(), split_balance_commit.to_vec(), 1)?;
        let settle = self
            .finish(
                Transaction {
                    version: 2,
                    inputs: vec![settle_in, proof_in, settle_fund],
                    outputs: vec![Output::new(1, out0), Output::new(1, out1), change_out(p2pkh_lock(&hash160(&to_a.pub_key())))],
                    ..Default::default()
                },
                false,
            )
            .await?;
        self.verify_and_log(&settle, "SPLIT SETTLE TX")?;
        self.tx = Some(settle.clone());
        self.vout_idx = 0;
        self.prev_txs.push(settle.clone());
        if let Some(s) = to_a.signer() {
            self.signer = Some(s);
        }
        self.pub_key = to_a.pub_key();
        self.pub_key_hash = hash160(&self.pub_key);
        self.balance = main_balance;

        let mut b = SimpleMultiBOLT::new();
        b.tx = Some(settle);
        b.vout_idx = 1;
        b.prev_txs = self.prev_txs.clone();
        b.signer = to_b.signer();
        b.pub_key = to_b.pub_key();
        b.pub_key_hash = hash160(&b.pub_key);
        b.issuer_pub_key = self.issuer_pub_key.clone();
        b.genesis_outpoint = self.genesis_outpoint.clone();
        b.balance = split_balance_commit.to_vec();
        b.skip_verify = self.skip_verify;
        Ok(b)
    }

    /// `melt(meltPubKeyHash?)` (None = the owner's pubKeyHash).
    pub async fn melt(&mut self, melt_pub_key_hash: Option<Vec<u8>>) -> Result<()> {
        let cur = self.cur_tx()?;
        let vout = cur.borrow().outputs.len() as u32 - 1;
        let pkh = melt_pub_key_hash.unwrap_or_else(|| self.pub_key_hash.clone());
        let tx = Transaction {
            version: 2,
            inputs: vec![
                input(&cur, self.vout_idx, Rc::new(SimpleMultiTemplate::melt(self.signer()?, None, None))),
                input(&cur, vout, Rc::new(P2PKHUnlock(self.signer()?))),
            ],
            outputs: vec![change_out(p2pkh_lock(&pkh))],
            ..Default::default()
        };
        let tx = self.finish(tx, false).await?;
        self.tx = Some(tx.clone());
        self.verify_and_log(&tx, "MELT TX")
    }
}

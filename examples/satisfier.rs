// SPDX-License-Identifier: CC0-1.0

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use bitcoin::{absolute, transaction, Amount, Network, OutPoint, PrivateKey, ScriptBuf, TapLeafHash, Transaction, TxIn, TxOut, Witness};
use bitcoin::taproot::Signature;
use secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey, Keypair};
use miniscript::policy::Concrete;
use miniscript::Satisfier;

fn main() {
	let secp = Secp256k1::new();
	
	let xonly_keys: Vec<XOnlyPublicKey> = [1u8, 2u8, 3u8]
		.iter()
		.map(|x| {
			let sk = SecretKey::from_slice(&[*x; 32]).unwrap();
			let kp = Keypair::from_secret_key(&secp, &sk);
			XOnlyPublicKey::from_keypair(&kp).0
		})
		.collect();
	
    let policy_str = format!("thresh(1,pk({}),pk({}),pk({}))", xonly_keys[0], xonly_keys[1], xonly_keys[2]);
    let policy = Concrete::<XOnlyPublicKey>::from_str(&policy_str).expect("parse policy");

    println!("Policy: {}", policy);
	
    let descriptor = policy
        .compile_tr(None)
        .expect("compile to taproot descriptor");

    println!("Compiled descriptor: {}", descriptor);
		
	let mut txin = TxIn {
		previous_output: OutPoint::default(),
		script_sig: ScriptBuf::new(),
		sequence: bitcoin::Sequence::from_height(1), // Or Sequence::ENABLE_LOCKTIME_NO_RBF if no specific sequence needed
		witness: Witness::default(),                 // Will be populated with the signature
	};
	
	println!("---- Calling `satisfy` where keyspend return Some(signature)");
	
	let keyspend_satisfier = TaprootSatisfier {key: None, keyspend_calls: Cell::new(0), tap_leaf_calls: RefCell::new(Default::default()) };
	descriptor.satisfy(&mut txin, keyspend_satisfier).expect("Failed to satisfy descriptor");
	
	println!("---- Calling `satisfy` where tapleaf for public key {} returns signature", xonly_keys[1]);
	
	let first_tapleaf_satisfier = TaprootSatisfier {key: Some(xonly_keys[1]), keyspend_calls: Cell::new(0), tap_leaf_calls: RefCell::new(Default::default()) };
	descriptor.satisfy(&mut txin, first_tapleaf_satisfier).expect("Failed to satisfy descriptor");
	
	println!("---- Calling `satisfy` where tapleaf for public key {} returns signature", xonly_keys[2]);
	
	let first_tapleaf_satisfier = TaprootSatisfier {key: Some(xonly_keys[2]), keyspend_calls: Cell::new(0), tap_leaf_calls: RefCell::new(Default::default()) };
	descriptor.satisfy(&mut txin, first_tapleaf_satisfier).expect("Failed to satisfy descriptor");
	
}


#[derive(Clone, Debug)]
struct TaprootSatisfier{
	/// Which key will return a signature?
	/// None means we will return the signature in keyspend
	key: Option<XOnlyPublicKey>,
	keyspend_calls: Cell<usize>,
	tap_leaf_calls: RefCell<HashMap<TapLeafHash, usize>>,
}

impl Satisfier<XOnlyPublicKey> for TaprootSatisfier {
	fn lookup_tap_leaf_script_sig(
		&self,
		pk: &XOnlyPublicKey,
		tap_leaf_hash: &TapLeafHash,
	) -> Option<bitcoin::taproot::Signature> {
		let mut map = self.tap_leaf_calls.borrow_mut();
		let number_of_calls = map.entry(*tap_leaf_hash).or_insert(0);
		*(number_of_calls)+=1;
		
		println!("Satisfier Tapleaf Hash {:?} - key {} - number of calls {:?}", tap_leaf_hash, pk, number_of_calls);
		if self.key == Some(*pk) {
			Some(Signature::from_slice(&[0u8;65]).unwrap())
		} else {
			None
		}
	}
	
	fn lookup_tap_key_spend_sig(&self) -> Option<Signature> {
		let next = self.keyspend_calls.get() + 1;
		self.keyspend_calls.set(next);
		
		println!("Satisfier Keyspend number of calls {}", self.keyspend_calls.get());
		
		if self.key.is_none() {
			Some(Signature::from_slice(&[1u8;65]).unwrap())
		} else {
			None
		}
	}
}

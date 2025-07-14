/// @author - Ola Hamid
/// @Title - zk_ecrecover
/// @notice -  implemented an ECDSA signature verification system using Noir, with a specific focus on mitigating signature malleability and replay attacks.
/// n: /*curved order*/ = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    /// e then we can check that s <= n/2
    /// e SECp256k1 used as curve order in decimal(as it's mainly used in Cryptography elliptic curves)
use dep::ecrecover;
// not needed again as i didn't change feild to array n the main branch
//use nodash::pack_bytes;
//----constant----//
// SECP256K1 CURVE ORDER N
fn _get_cover_order() -> ([u8; 32]) {
    let CURVE_ODER: [u8; 32] = [ 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ];
    (CURVE_ODER)
}
fn get_half_cover_order() -> ([u8; 32]) {
    let HALF_CURVE_ORDER: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
        0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0
    ];

    HALF_CURVE_ORDER
}

//----data----//
struct EcrValue {
    signature_r: [u8; 32],
    signature_s: [u8; 32],
    full_signature: [u8; 64],
    half_n: [u8; 32],
    full_n: [u8; 32],
}

//----Effect----//
trait compute_Ecrecover {
    fn extract_signature_values(&mut self, sig: [u8; 64]);
    fn is_signature_safe(&mut self) -> bool;
}

impl compute_Ecrecover for EcrValue {
    fn extract_signature_values(
        &mut self, 
        sig: [u8; 64]) 
    {
        
        for i in 0..32 {
            self.signature_r[i] = sig[i];
            self.signature_s[i] = sig[i + 32];
        }
        // store the total sig in the struct 
        self.full_signature = sig;
        // store the total to the half cover order
        self.half_n = get_half_cover_order();

        // store the total to the full coveer order
        self.full_n = _get_cover_order();
    }
    
    fn is_signature_safe(
        &mut self
    ) -> bool {

        let s = self.signature_s;
        let n_half = self.half_n;
        let mut is_safe = false;
        let mut is_break = false;
        // compare s with n_half byte by byte 
        for i in 0..32 {
            if (is_break == false) {
                if (s[i] < n_half[i]) {
                    is_safe =  true;
                    is_break = true; 
                } else if(s[i] > n_half[i]) {
                    is_safe = false;
                    is_break = true;
                }
            // if the the both bytes are equal coninue to the next bytes
            }
        }
        is_safe
    }

}   

fn main (
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64], // r and s components concatenated
    hashed_message: [u8; 32],
    expected_address: Field, 
) -> pub ( bool, Field) {
    
    //get_cover_order();
    let mut _ecr_values = EcrValue {
        signature_r: [0; 32],
        signature_s: [0; 32],
        full_signature: [0; 64],
        half_n: [0; 32],
        full_n: [0; 32],
    };
    // setting data value.
    _ecr_values.extract_signature_values(signature);

    // making effect
    let is_safe = _ecr_values.is_signature_safe();
    
    let address: Field = ecrecover::ecrecover(pub_key_x, pub_key_y, signature, hashed_message);
    assert(is_safe, "the signature is not safe: s> n");
    assert(address == expected_address, "resulting address is not the same as expecte address");

    (is_safe, address)
    
}




// use dep::ecrecover;
// //use std::static_assert;
// fn main(
//     pub_key_x: [u8; 32],
//     pub_key_y: [u8; 32],
//     signature: [u8; 64], // r and s components concatenated
//     hashed_message: [u8; 32],
//     expected_address: Field // The Ethereum address derived from the public key
// ) {
//     // The ecrecover function attempts to recover an Ethereum address
//     // from the public key, signature, and hashed message.
//     // The 'false' argument indicates an Ethereum non-prefixed hash.
//     let address: Field = ecrecover::ecrecover(pub_key_x, pub_key_y, signature, hashed_message);
    
//     // Assert that the recovered address matches the expected address.
//     // If they don't match, the proof will fail.
//     assert(address == expected_address, "Address does not match expected address");
// }

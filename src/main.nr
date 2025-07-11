/// @author - Ola Hamid
/// @Title - zk_ecrecover
/// @notice -  implemented an ECDSA signature verification system using Noir, with a specific focus on mitigating signature malleability and replay attacks.
/// n: /*curved order*/ = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    /// e then we can check that s <= n/2
    /// e SECp256k1 used as curve order in decimal(as it's mainly used in Cryptography elliptic curves)
use dep::ecrecover;
use std::static_assert;
// not needed again as i didn't change t
//use nodash::pack_bytes;

///----data---///
struct ecr_values {
    byte_r: [u8; 32],
    byte_s: [u8; 32],
    signature_sig: [u8; 64],
    feild_s : Field,
    halfN: Field,
    // log_r: Field,
    // log_s: Field,
}
trait do_ECR_computation {
    fn sig_parts_to_array(&mut self, is_s_part: bool) -> [u8; 32];
    fn is_s_less_than_half_n(_s: [u8; 32], _n: [u8; 32]) -> bool;
    /* todo i want to have something like an enum functionality that say the var that is beingpassed in the function below
    if the enum is r it stores it in the ecr_values.byte_r, s it stores it in ecr_values.byte_s, and sig it stores it in ecr_values.signature_sig.
    */
    fn compute_field_to_array(_f: Field) -> [u8; 32]; 
}


impl do_ECR_computation for ecr_values {
    fn sig_parts_to_array(&mut self, is_s_part: bool) -> [u8; 32] {

        // the goal here is to convert the sig_parts struct into a byte array of 32 bytes
        // if ((self.part0 != self.part1) | (self.part2 != self.part3) | (self.part0 != self.part2)) {
        //     static_assert(false, "part0 and part1 must be equal");
        // }
        // assuming part is divided into equal 16 parts
        let mut total_bytes: [u8; 32] = [0; 32];
        if (is_s_part == true) {
            let part = self.feild_s;
        
            let mut arr_part0: [u8; 8] = [0; 8];
            let mut arr_part1: [u8; 8] = [0; 8];
            let mut arr_part2: [u8; 8] = [0; 8];
            let mut arr_part3: [u8; 8] = [0; 8];
            // ensure that each part is less than 64 bits
            self.feild_s.assert_max_bit_size::<64>();
            arr_part0 = part.to_be_bytes();
            arr_part1 = part.to_be_bytes();
            arr_part2 = part.to_be_bytes();
            arr_part3 = part.to_be_bytes();
            for i in 0..8 {
                total_bytes[i] = arr_part0[i];
            }

            for i in 0..8 {
                total_bytes[i + 8] = arr_part1[i];
            }
            for i in 0..8 {
                total_bytes[i + 16] = arr_part2[i];
            }
            for i in 0..8 {
                total_bytes[i + 24] = arr_part3[i];
            }
        } else {
            let part = self.halfN;
        
            let mut arr_part0: [u8; 8] = [0; 8];
            let mut arr_part1: [u8; 8] = [0; 8];
            let mut arr_part2: [u8; 8] = [0; 8];
            let mut arr_part3: [u8; 8] = [0; 8];
            // ensure that each part is less than 64 bits
            self.feild_s.assert_max_bit_size::<64>();
            arr_part0 = part.to_be_bytes();
            arr_part1 = part.to_be_bytes();
            arr_part2 = part.to_be_bytes();
            arr_part3 = part.to_be_bytes();
            for i in 0..8 {
                total_bytes[i] = arr_part0[i];
            }

            for i in 0..8 {
                total_bytes[i + 8] = arr_part1[i];
            }
            for i in 0..8 {
                total_bytes[i + 16] = arr_part2[i];
            }
            for i in 0..8 {
                total_bytes[i + 24] = arr_part3[i];
            }
        }
        total_bytes 
    }
    fn is_s_less_than_half_n(_s: [u8; 32], h_n:[u8; 32]) -> bool {
        // check that _s <= _n/2
        let mut result = true;
        for i in 0..32 {
            if (_s[i] < h_n[i]) {
                result = true; // s is less than n/2
                
            } else if (_s[i] > h_n[i]) {
                result = false; // s is greater than n/2
            }  
        }
        true 
    }
    
    fn compute_field_to_array(_f: Field) -> [u8; 32] {
        static_assert( _f  != 0 , "Field must be greater than 0");
        _f.to_be_bytes()
    }
    // fn compute_array_to_field(_arr: [u8; 32]) -> Field {
    //     let _f = pack_bytes(_arr);
    //     _f[0]
    //     // solidty is 2^256 max while noir max is 2^64
    //     //  curve order for 
    // }
}
// impl do_ecrecover_check for ecr_values {
    
// }
///----implementation---///
/** 
*/
fn main(
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    mut arr_signature: [u8; 64],
    message_hash: [u8; 32],
    expected_address: Field,
    F_r_signature_div16: Field,
    F_s_signature_div16: Field,
) -> pub (bool, Field) {
    let mut if_arr_used: bool = false;
    // check if the r and s sig is more that zero hence want to use  ininteger in checking the value result  
    if ((F_r_signature_div16 == 0) | (F_s_signature_div16 == 0)) {
        if_arr_used = false;
    }
    // secp256k1 curve order
    let mut arr_curved_order: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41, 
    ];
    // used to convert Field to array then do the check in array/byte
    let curved_order_div16: Field = 7237005577332262213973186563042993990802347767442181523912822696344885093396;

    let mut _ecr_values = ecr_values {
        byte_r: [0; 32],
        byte_s: [0; 32],
        signature_sig: [0; 64],
        feild_s : 0,
        halfN: 0
         // n/2
    };
    _ecr_values.feild_s = F_s_signature_div16;
    _ecr_values.halfN = curved_order_div16;

    // step1- spit the signature into r and s
    let mut r: [u8; 32] = [0; 32];
    let mut s: [u8; 32] = [0; 32];

    let mut is_valid = false;
    if (if_arr_used == false) {
        let _Field_to_arr_SigS = _ecr_values.sig_parts_to_array(true);
        let _field_to_arr_SigHALFN = _ecr_values.sig_parts_to_array(false );
        s = _Field_to_arr_SigS;
        arr_curved_order = _field_to_arr_SigHALFN;

        is_valid = ecr_values::is_s_less_than_half_n(s, arr_curved_order);
    }
    else {
            for i in 0..32 {
            r[i] = arr_signature[i]; // first 32 bytes of signature is r
            s[i] = arr_signature[i + 32]; // last 32 bytes of signature is s
        }  
        // note that the second param represention curved order value passed in the function below
        //let is_valid = _ecr_values.is_s_less_than_half_n(s, curved_order_div2);
        is_valid = ecr_values::is_s_less_than_half_n(s, arr_curved_order);
    }
    for i in 0..32 {
        _ecr_values.signature_sig[i] = r[i];
        _ecr_values.signature_sig[i + 32] = s[i];
    }


    _ecr_values.byte_s = s;
    _ecr_values.byte_r = r;

    let address = ecrecover::ecrecover(pub_key_x, pub_key_y, arr_signature, message_hash);

    std::println( address);
    assert(expected_address == address, "address checked sucessfully!");
    assert(is_valid == true, "valid message is false");

    (is_valid, expected_address)
}

// #[test]
// fn test_main() {
//     main(1, 2);

//     // Uncomment to make test fail
//     // main(1, 1);
// }

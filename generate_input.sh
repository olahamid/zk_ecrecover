#!/bin/bash

input_file="inputs.txt"
output_file="Prover.toml"

# Extract only the value inside quotes for a given key
extract_value() {
    local key=$1
    # Extract the part inside quotes after the equals sign
    grep "^$key\s*=" "$input_file" | sed -E 's/^[^=]+= *"(.*)"/\1/'
}

# Convert hex string (without 0x) to quoted decimal byte array
hex_to_dec_quoted_array() {
    local hexstr=$1
    # Ensure hex string is exactly 64 characters (32 bytes) by padding with zeros
    printf -v padded_hex "%064s" "$hexstr"
    padded_hex=${padded_hex// /0}
    
    local len=${#padded_hex}
    local arr=()
    for (( i=0; i<len; i+=2 )); do
        # Extract two hex digits
        local hexbyte="${padded_hex:i:2}"
        # Convert hex to decimal number
        local dec=$((16#$hexbyte))
        # Add decimal number as quoted string
        arr+=("\"$dec\"")
    done
    echo "["$(IFS=,; echo "${arr[*]}")"]"
}

# Convert decimal string to 32-byte hex using bc, then to quoted decimal byte array
dec_to_32byte_quoted_array() {
    local dec_str=$1
    # Use bc to convert decimal to hex (handles large numbers)
    local hex_str=$(echo "obase=16; $dec_str" | bc | tr 'A-F' 'a-f')
    # Pad to 64 characters (32 bytes)
    printf -v padded_hex "%064s" "$hex_str"
    padded_hex=${padded_hex// /0}
    
    hex_to_dec_quoted_array "$padded_hex"
}

# Read values from file
expected_address=$(extract_value expected_address)
hashed_message=$(extract_value hashed_message)
pub_key_x=$(extract_value pub_key_x)
pub_key_y=$(extract_value pub_key_y)
signature=$(extract_value signature)

# Strip 0x from hex values
hashed_message=${hashed_message#0x}
signature=${signature#0x}

# Strip last byte (2 hex chars) from signature to remove v
signature=${signature:0:${#signature}-2}

# Convert values to proper format
hashed_message_arr=$(hex_to_dec_quoted_array "$hashed_message")
pub_key_x_arr=$(dec_to_32byte_quoted_array "$pub_key_x")
pub_key_y_arr=$(dec_to_32byte_quoted_array "$pub_key_y")
signature_arr=$(hex_to_dec_quoted_array "$signature")

# Write output
cat > "$output_file" <<EOF
expected_address = "$expected_address"
hashed_message = $hashed_message_arr
pub_key_x = $pub_key_x_arr
pub_key_y = $pub_key_y_arr
signature = $signature_arr
EOF

echo "Wrote $output_file"
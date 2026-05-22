import numpy as np
import cv2
import os
import wave

# ------------------ TEXT STEGANOGRAPHY ------------------ #
ZWC = {"00": u'\u200C', "01": u'\u202C', "11": u'\u202D', "10": u'\u200E'}
ZWC_reverse = {v: k for k, v in ZWC.items()}

def txt_encode(text, cover_text_path, output_file):
    print(f"DEBUG txt_encode: Input text length: {len(text)}")
    print(f"DEBUG txt_encode: Cover file: {cover_text_path}")
    print(f"DEBUG txt_encode: Output file: {output_file}")
    
    l = len(text)
    i = 0
    add = ''
    while i < l:
        t = ord(text[i])
        if 32 <= t <= 64:
            t1 = t + 48
            t2 = t1 ^ 170
            res = bin(t2)[2:].zfill(8)
            add += "0011" + res
        else:
            t1 = t - 48
            t2 = t1 ^ 170
            res = bin(t2)[2:].zfill(8)
            add += "0110" + res
        i += 1
    res1 = add + "111111111111"
    
    print(f"DEBUG txt_encode: Binary data length: {len(res1)} bits")

    HM_SK = ""
    try:
        with open(cover_text_path, "r", encoding="utf-8", errors='ignore') as file1, open(output_file, "w", encoding="utf-8") as file3:
            word = []
            for line in file1:
                word += line.split()
            
            print(f"DEBUG txt_encode: Cover text has {len(word)} words")
            
            # SAFETY CHECK: Ensure we have cover text
            if not word:
                word = ["Safe", "Cover", "Text", "Generated", "By", "System"]
                print("DEBUG txt_encode: Using default cover text")

            zwc_chars_written = 0
            i = 0
            while i < len(res1):
                # Modular arithmetic to cycle through words if cover text is too short
                s = word[int(i/12) % len(word)]
                j = 0
                HM_SK = ""
                while j < 12:
                    if j+i+1 < len(res1):
                        x = res1[j+i] + res1[i+j+1]
                        HM_SK += ZWC[x]
                        zwc_chars_written += 1
                    j += 2
                file3.write(s + HM_SK + " ")
                i += 12
            
            print(f"DEBUG txt_encode: ZWC characters written: {zwc_chars_written}")
            
    except Exception as e:
        print(f"DEBUG txt_encode ERROR: {e}")
        return f"Error: {e}"
        
    print("DEBUG txt_encode: Encoding completed successfully")
    return "Stego text file generated successfully"

def decode_txt_data(stego_file):
    temp = ''
    debug_info = []
    
    try:
        # Read the entire file content
        with open(stego_file, "r", encoding="utf-8", errors='ignore') as file4:
            content = file4.read()
            
        debug_info.append(f"File size: {len(content)} chars")
        
        # Count ZWC characters found
        zwc_count = 0
        for char in content:
            if char in ZWC_reverse:
                temp += ZWC_reverse[char]
                zwc_count += 1
                
        debug_info.append(f"ZWC characters found: {zwc_count}")
        debug_info.append(f"Binary bits extracted: {len(temp)}")
        
        # Check for terminator
        if "111111111111" in temp:
             temp = temp.split("111111111111")[0]
             debug_info.append("Terminator found and removed")
        else:
            debug_info.append("No terminator found")
             
    except Exception as e:
        debug_info.append(f"Read error: {e}")

    # If no bits found, return empty but log what we found
    if len(temp) == 0:
        print("DEBUG decode_txt_data:", "; ".join(debug_info))
        return ""

    # Decode the binary data
    lengthd = len(temp)
    i = 0
    a, b, c, d = 0, 4, 4, 12
    final = []
    
    try:
        while i < len(temp) and a + 4 <= len(temp) and c + 4 <= len(temp):
            if a + 12 > len(temp) or c + 12 > len(temp):
                break
                
            t3 = temp[a:b]
            t4 = temp[c:d]
            
            a += 12
            b += 12
            c += 12
            d += 12
            i += 12
            
            if t3 == '0110':
                decimal_val = int(t4, 2) ^ 170 + 48
                final.append(chr(decimal_val))
            elif t3 == '0011':
                decimal_val = int(t4, 2) ^ 170 - 48
                final.append(chr(decimal_val))
                
    except Exception as e:
        debug_info.append(f"Decode error: {e}")
        
    result = "".join(final)
    debug_info.append(f"Final result length: {len(result)}")
    
    # Always print debug for text files to help diagnose
    print("DEBUG decode_txt_data:", "; ".join(debug_info))
    
    return result

# ------------------ IMAGE STEGANOGRAPHY ------------------ #
def msgtobinary(msg):
    if type(msg) == str:
        return ''.join([format(ord(i), "08b") for i in msg])
    elif type(msg) in [bytes, np.ndarray]:
        return [format(i, "08b") for i in msg]
    elif type(msg) in [int, np.uint8]:
        return format(msg, "08b")
    else:
        raise TypeError("Unsupported input type")

def encode_img_data(img, secret_text, output_file='stego_image.png'):
    data = secret_text + '*^*^*'
    binary_data = msgtobinary(data)
    index_data = 0
    for i in img:
        for pixel in i:
            r, g, b = msgtobinary(pixel)
            if index_data < len(binary_data):
                pixel[0] = int(r[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data < len(binary_data):
                pixel[1] = int(g[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data < len(binary_data):
                pixel[2] = int(b[:-1] + binary_data[index_data], 2)
                index_data += 1
            if index_data >= len(binary_data):
                break
    cv2.imwrite(output_file, img)
    return output_file

def decode_img_data(img):
    data_binary = ""
    # Efficient pre-calculation of binary data
    # Flatten image to loop once instead of nested loops
    flattened_img = img.reshape(-1, 3) 
    
    # We only need enough bits to find the terminator '*^*^*'
    # But usually we must scan a lot.
    # To avoid memory issues with huge strings, let's process in chunks.
    
    chunk_size = 1000 # process 1000 pixels at a time
    current_binary_chunk = []
    
    # We need to reconstruct bytes from bits.
    # 3 bits per pixel (R, G, B LSBs)
    
    all_bits = []
    
    for pixel in flattened_img:
        # Simple extraction using bitwise operations (faster than string format)
        all_bits.append(str(pixel[0] & 1))
        all_bits.append(str(pixel[1] & 1))
        all_bits.append(str(pixel[2] & 1))
        
        # Check every ~1000 pixels (3000 bits) if we have enough for a full check
        if len(all_bits) > 8000: # ~1KB of data
             # Convert accumulated bits to chars
             # We need multiples of 8
             num_bytes = len(all_bits) // 8
             if num_bytes > 0:
                 # Join bits to string
                 bit_str = "".join(all_bits[:num_bytes*8])
                 # Convert to chars
                 chars = ""
                 for i in range(0, len(bit_str), 8):
                     byte = bit_str[i:i+8]
                     chars += chr(int(byte, 2))
                 
                 # Check terminator
                 if "*^*^*" in chars:
                     return chars.split("*^*^*")[0]
                     
                # Optimization: The terminator might be split across chunks.
                # In a robust system, we handle that. 
                # For this simple fix, let's just allow it to grow but stop if huge.
                # Actually, this streaming check is complex to get right quickly.
                # Let's revert to a slightly safer "Load All" but optimized.
                
    # Revert to simpler logic but with bitwise speedup
    bits_list = []
    for pixel in flattened_img:
        bits_list.append(str(pixel[0] & 1))
        bits_list.append(str(pixel[1] & 1))
        bits_list.append(str(pixel[2] & 1))
        
    bit_string = "".join(bits_list)
    
    # Convert to bytes
    decoded_data = ""
    # 8 bits = 1 char
    # Stop early if we find terminator
    
    # More efficient char conversion
    # Process 8 bits at a time
    for i in range(0, len(bit_string), 8):
        if i + 8 > len(bit_string): break
        byte = bit_string[i:i+8]
        char = chr(int(byte, 2))
        decoded_data += char
        
        # Check every 100 chars for terminator to exit early
        if i % 800 == 0:
            if decoded_data.endswith("*^*^*"):
                return decoded_data[:-5]
                
    if "*^*^*" in decoded_data:
        return decoded_data.split("*^*^*")[0]
    return ""

# ------------------ AUDIO STEGANOGRAPHY ------------------ #
def encode_aud_data(audio_path, secret_text, output_file='stego_audio.wav'):
    song = wave.open(audio_path, mode='rb')
    nframes = song.getnframes()
    frames = song.readframes(nframes)
    frame_bytes = bytearray(list(frames))
    data = secret_text + '*^*^*'
    result = []
    for c in data:
        bits = bin(ord(c))[2:].zfill(8)
        result.extend([int(b) for b in bits])
    j = 0
    for i in range(len(result)):
        res = bin(frame_bytes[j])[2:].zfill(8)
        if res[-4] == result[i]:
            frame_bytes[j] = frame_bytes[j] & 253
        else:
            frame_bytes[j] = (frame_bytes[j] & 253) | 2
            frame_bytes[j] = (frame_bytes[j] & 254) | result[i]
        j += 1
    frame_modified = bytes(frame_bytes)
    with wave.open(output_file, 'wb') as fd:
        fd.setparams(song.getparams())
        fd.writeframes(frame_modified)
    song.close()
    return output_file

def decode_aud_data(audio_path):
    song = wave.open(audio_path, mode='rb')
    nframes = song.getnframes()
    frames = song.readframes(nframes)
    frame_bytes = bytearray(list(frames))
    extracted = ""
    p = 0
    for i in range(len(frame_bytes)):
        if p == 1:
            break
        res = bin(frame_bytes[i])[2:].zfill(8)
        if res[-2] == '0':
            extracted += res[-4]
        else:
            extracted += res[-1]
        all_bytes = [extracted[i:i+8] for i in range(0, len(extracted), 8)]
        decoded_data = ""
        for byte in all_bytes:
            decoded_data += chr(int(byte, 2))
            if decoded_data[-5:] == "*^*^*":
                return decoded_data[:-5]

# ------------------ VIDEO STEGANOGRAPHY ------------------ #
def encryption(plaintext, key):
    key_array = [ord(c) for c in key]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_array[i % len(key_array)]) % 256
        S[i], S[j] = S[j], S[i]
    keystream = []
    i = j = 0
    for _ in range(len(plaintext)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i]+S[j])%256])
    cipher = [keystream[k] ^ ord(c) for k, c in enumerate(plaintext)]
    return ''.join([chr(c) for c in cipher])

def decryption(ciphertext, key):
    key_array = [ord(c) for c in key]
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_array[i % len(key_array)]) % 256
        S[i], S[j] = S[j], S[i]
    keystream = []
    i = j = 0
    for _ in range(len(ciphertext)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i]+S[j])%256])
    decoded = [keystream[k] ^ ord(c) for k, c in enumerate(ciphertext)]
    return ''.join([chr(c) for c in decoded])

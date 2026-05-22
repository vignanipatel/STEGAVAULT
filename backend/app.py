from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import numpy as np
import cv2
import wave
import tempfile
import base64
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter

# ------------------ Initialize Flask ------------------ #
app = Flask(__name__)
CORS(app, expose_headers=["Content-Disposition"])

# Add request logging for debugging
@app.before_request
def log_request():
    print(f"DEBUG: Request to {request.endpoint} - {request.method} {request.path}")
    print(f"DEBUG: Files: {list(request.files.keys())}")
    print(f"DEBUG: Form: {dict(request.form)}")

# ------------------ TEXT STEGANOGRAPHY ------------------ #
ZWC = {"00": u'\u200C', "01": u'\u202C', "11": u'\u202D', "10": u'\u200E'}
ZWC_reverse = {v: k for k, v in ZWC.items()}

def txt_encode(text, cover_text_path, output_file):
    # convert text to binary
    binary_text = ''.join([format(ord(char), '08b') for char in text])
    # termination marker
    binary_text += '010101010101'  # 12-bit termination marker

    with open(cover_text_path, "r", encoding="utf-8") as file:
        words = file.read().split()

    required_words = (len(binary_text) // 12) + 1
    if required_words > len(words):
        raise ValueError(f"Cover text too short! Needs at least {required_words} words, but only {len(words)} provided.")

    with open(output_file, "w", encoding="utf-8") as file:
        for i, word in enumerate(words):
            if i * 12 < len(binary_text):
                start_idx = i * 12
                end_idx = min((i + 1) * 12, len(binary_text))
                bits = binary_text[start_idx:end_idx]
                zwc_chars = ''.join(ZWC[bits[j:j+2]] for j in range(0, len(bits), 2))
                file.write(word + zwc_chars + " ")
            else:
                file.write(word + " ")

def decode_txt_data(stego_file):
    binary_data = ""
    with open(stego_file, "r", encoding="utf-8") as file:
        content = file.read()
        for char in content:
            if char in ZWC_reverse:
                binary_data += ZWC_reverse[char]

    term_pattern = "010101010101"
    term_pos = binary_data.find(term_pattern)
    if term_pos != -1:
        binary_data = binary_data[:term_pos]

    text = ""
    for i in range(0, len(binary_data), 8):
        if i + 8 <= len(binary_data):
            byte = binary_data[i:i+8]
            try:
                text += chr(int(byte, 2))
            except:
                continue
    return text

# ------------------ IMAGE STEGANOGRAPHY ------------------ #
def msgtobinary(msg):
    if isinstance(msg, str):
        return ''.join([format(ord(i), "08b") for i in msg])
    elif isinstance(msg, (bytes, np.ndarray)):
        return [format(i, "08b") for i in msg]
    elif isinstance(msg, (int, np.uint8)):
        return format(msg, "08b")
    else:
        raise TypeError("Unsupported input type")

def encode_img_data(img, secret_text, output_file):
    data = secret_text + '*^*^*'
    binary_data = msgtobinary(data)
    index_data = 0
    # iterate pixels
    for row in img:
        for pixel in row:
            for k in range(3):
                if index_data < len(binary_data):
                    pixel[k] = (pixel[k] & 0b11111110) | int(binary_data[index_data])
                    index_data += 1
            if index_data >= len(binary_data):
                break
    cv2.imwrite(output_file, img)

def decode_img_data(img):
    data_binary = ""
    for row in img:
        for pixel in row:
            for k in range(3):
                data_binary += str(pixel[k] & 1)
    all_bytes = [data_binary[i:i+8] for i in range(0, len(data_binary), 8)]
    decoded_data = ""
    for byte in all_bytes:
        try:
            decoded_data += chr(int(byte, 2))
            if decoded_data.endswith("*^*^*"):
                return decoded_data[:-5]
        except:
            continue
    return decoded_data

# ------------------ VIDEO STEGANOGRAPHY (AES Version) ------------------ #

def derive_key(password, salt=None):
    """Derive a 32-byte (256-bit) key from password"""
    if salt is None:
        salt = get_random_bytes(16)
    # Use SHA-256 for key derivation
    key = hashlib.sha256(password.encode() + salt).digest()
    return key, salt

def encryption(plaintext, key):
    """Encrypt using AES-CTR mode"""
    try:
        # Derive key from password
        derived_key, salt = derive_key(key)
        
        # Generate random nonce for CTR mode
        nonce = get_random_bytes(8)
        
        # Create counter for CTR mode
        ctr = Counter.new(64, prefix=nonce, initial_value=0)
        
        # Create AES-CTR cipher
        cipher = AES.new(derived_key, AES.MODE_CTR, counter=ctr)
        
        # Encrypt the plaintext
        ciphertext = cipher.encrypt(plaintext.encode())
        
        # Return salt + nonce + ciphertext (all as base64)
        combined = salt + nonce + ciphertext
        return base64.b64encode(combined).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return ""

def decryption(ciphertext, key):
    """Decrypt using AES-CTR mode"""
    try:
        # Clean and Fix Base64 Padding
        ciphertext = ciphertext.strip()
        missing_padding = len(ciphertext) % 4
        if missing_padding:
            ciphertext += '=' * (4 - missing_padding)
            
        # Decode from base64
        combined = base64.b64decode(ciphertext)
        
        # Extract components: salt(16) + nonce(8) + actual_ciphertext
        if len(combined) < 24: # Validation
            print("DEBUG: Decryption failed - payload too short")
            return ""

        salt = combined[:16]
        nonce = combined[16:24]
        actual_ciphertext = combined[24:]
        
        # Derive key using the same salt
        derived_key, _ = derive_key(key, salt)
        
        # Recreate counter for CTR mode
        ctr = Counter.new(64, prefix=nonce, initial_value=0)
        
        # Create AES-CTR cipher
        cipher = AES.new(derived_key, AES.MODE_CTR, counter=ctr)
        
        # Decrypt
        plaintext = cipher.decrypt(actual_ciphertext)
        
        try:
             return plaintext.decode('utf-8')
        except UnicodeDecodeError:
             # Fallback for binary data that isn't utf-8 text
             # We return base64 of the binary if it fails decoding?
             # Or just latin-1? 
             # For this app, secrets are usually text. 
             # If it fails, it might be the key is wrong producing garbage.
             return plaintext.decode('latin-1') 

    except Exception as e:
        print(f"DEBUG: Decryption error: {e}")
        # Return empty string on error (matching original behavior)
        return ""

def embed_frame(frame, secret_text, key):
    """Embed encrypted secret text into video frame using LSB steganography"""
    frame = frame.copy()
    
    # Encrypt the secret text
    data = encryption(secret_text, key)
    if data == "":  # Encryption failed
        raise ValueError("Encryption failed")
    
    # Add termination marker (same as original)
    data_with_marker = data + '*^*^*'
    
    # Convert to binary
    binary_data = ''.join([format(ord(i), '08b') for i in data_with_marker])
    
    # Embed in LSB of pixels
    index_data = 0
    height, width = frame.shape[:2]
    
    for i in range(height):
        for j in range(width):
            pixel = frame[i][j]
            for k in range(3):  # R, G, B channels
                if index_data < len(binary_data):
                    # Preserve 7 MSBs, replace LSB with our data bit
                    pixel[k] = (pixel[k] & 0b11111110) | int(binary_data[index_data])
                    index_data += 1
            if index_data >= len(binary_data):
                return frame
    
    return frame

def extract_frame(frame, key):
    """Extract and decrypt secret text from video frame"""
    data_binary = ""
    
    # Extract LSBs from all pixels
    for row in frame:
        for pixel in row:
            for k in range(3):  # R, G, B channels
                data_binary += str(pixel[k] & 1)
    
    # Convert binary to text
    all_bytes = [data_binary[i:i+8] for i in range(0, len(data_binary), 8)]
    decoded_data = ''
    
    for b in all_bytes:
        try:
            if len(b) == 8:
                decoded_data += chr(int(b, 2))
        except:
            continue
    
    # Find termination marker
    if "*^*^*" in decoded_data:
        encoded_ciphertext = decoded_data.split("*^*^*")[0]
        
        # Try to decrypt
        try:
            return decryption(encoded_ciphertext, key)
        except:
            return ""
    
    return ""

# ------------------ AUDIO STEGANOGRAPHY ------------------ #
def encode_aud_data(audio_path, secret_text, output_file):
    try:
        song = wave.open(audio_path, mode='rb')
    except wave.Error:
        raise ValueError("Invalid audio format! Audio Steganography requires uncompressed WAV files.")
        
    params = song.getparams()
    n_frames = song.getnframes()
    frames = song.readframes(n_frames)
    
    # Convert audio frames to numpy array (mutable)
    # wav frames are just bytes (uint8)
    cover_arr = np.frombuffer(frames, dtype=np.uint8).copy()
    
    # Prepare payload
    # Add terminator
    data = secret_text + '*^*^*'
    # Convert string to bytes
    data_bytes = data.encode('utf-8', errors='surrogatepass') # Use surrogatepass to handle binary data hidden in string
    
    # Create numpy array of payload bits
    payload_arr = np.frombuffer(data_bytes, dtype=np.uint8)
    payload_bits = np.unpackbits(payload_arr)
    
    if len(payload_bits) > len(cover_arr):
        song.close()
        raise ValueError(f"Audio file too short. Needed {len(payload_bits)} samples, got {len(cover_arr)}.")
        
    # Vectorized Embedding using slicing
    # We only modify the first N bytes where N is len(payload_bits)
    # LSB substitution: (byte & 0xFE) | bit
    
    # Mask out LSB of cover
    cover_arr[:len(payload_bits)] &= 0b11111110
    # OR with payload bits
    cover_arr[:len(payload_bits)] |= payload_bits
    
    with wave.open(output_file, 'wb') as fd:
        fd.setparams(params)
        fd.writeframes(cover_arr.tobytes())
    song.close()

def decode_aud_data(audio_path):
    try:
        song = wave.open(audio_path, mode='rb')
    except wave.Error:
        return ""
        
    frames = song.readframes(song.getnframes())
    cover_arr = np.frombuffer(frames, dtype=np.uint8)
    
    # Vectorized Extraction
    # Extract LSBs
    bits = cover_arr & 1
    
    # Pack bits back into bytes
    # np.packbits packs 8 bits into a byte. 
    # It assumes bits are [b7, b6, ... b0] (big endian within byte) by default or can vary.
    # Our encode was: char -> bin(x) -> bits. bin(x) gives high-to-low.
    # np.unpackbits also gives high-to-low (most significant bit first).
    # So packing simply reverses unpacking.
    
    try:
        # We process all bytes, so we might have trailing garbage bits that don't make full bytes.
        # Truncate to multiple of 8
        valid_bits = bits[:len(bits)//8 * 8]
        packed_bytes = np.packbits(valid_bits)
        
        # We need to find the terminator in the byte string
        # Decoding might fail if we just blindly decode 'utf-8' on random noise at the end of file.
        # So we work with bytes first.
        
        raw_bytes = packed_bytes.tobytes()
        TERMINATOR = b'*^*^*'
        
        # Find terminator
        t_index = raw_bytes.find(TERMINATOR)
        if t_index != -1:
            raw_bytes = raw_bytes[:t_index]
            
        # Decode to string
        return raw_bytes.decode('utf-8', errors='surrogatepass')
        
    except Exception as e:
        print(f"Audio Decode Error: {e}")
        return ""

# ------------------ FLASK ENDPOINTS ------------------ #
@app.route('/text/encode', methods=['POST'])
def text_encode_endpoint():
    try:
        text = request.form['text']
        cover_file = request.files['file']
        tmp_cover = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        tmp_cover.close()
        cover_file.save(tmp_cover.name)
        output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        output_file.close()
        txt_encode(text, tmp_cover.name, output_file.name)
        try: os.remove(tmp_cover.name)
        except: pass
        return send_file(output_file.name, as_attachment=True, download_name="stego_text.txt")
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/text/decode', methods=['POST'])
def text_decode_endpoint():
    try:
        print("DEBUG: /text/decode endpoint called")
        print(f"DEBUG: Request files: {list(request.files.keys())}")
        print(f"DEBUG: Request form: {dict(request.form)}")
        
        stego_file = request.files['file']
        key = request.form.get('key', 'default-key')
        
        print(f"DEBUG: File name: {stego_file.filename}")
        print(f"DEBUG: Key: {key}")
        
        tmp_stego = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        tmp_stego.close()
        stego_file.save(tmp_stego.name)
        
        # Extract the encrypted data using steganography
        encrypted_data = decode_txt_data(tmp_stego.name)
        print(f"DEBUG: Encrypted data length: {len(encrypted_data) if encrypted_data else 0}")
        
        try: os.remove(tmp_stego.name)
        except: pass
        
        if not encrypted_data:
            print("DEBUG: No encrypted data found")
            return jsonify({"error": "No hidden data found"}), 400
            
        # Decrypt the extracted data
        decrypted_text = decryption(encrypted_data, key)
        print(f"DEBUG: Decrypted text length: {len(decrypted_text) if decrypted_text else 0}")
        
        if not decrypted_text:
            print("DEBUG: Decryption failed")
            return jsonify({"error": "Failed to decrypt data. Check your key."}), 400
            
        print(f"DEBUG: Success! Returning decrypted text")
        return jsonify({"decoded_text": decrypted_text})
    except Exception as e:
        print(f"DEBUG: Exception in text_decode_endpoint: {e}")
        return jsonify({"error": str(e)}), 400

@app.route('/image/encode', methods=['POST'])
def image_encode_endpoint():
    try:
        file = request.files['image']
        secret_text = request.form.get('text', '')
        tmp_image = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        tmp_image.close()
        file.save(tmp_image.name)
        img = cv2.imread(tmp_image.name)
        if img is None:
            try: os.remove(tmp_image.name)
            except: pass
            return jsonify({"error": "Invalid image"}), 400
        output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        output_file.close()
        encode_img_data(img, secret_text, output_file.name)
        try: os.remove(tmp_image.name)
        except: pass
        return send_file(output_file.name, as_attachment=True, download_name="stego_image.png")
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/image/decode', methods=['POST'])
def image_decode_endpoint():
    try:
        file = request.files['image']
        tmp_image = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        tmp_image.close()
        file.save(tmp_image.name)
        img = cv2.imread(tmp_image.name)
        if img is None:
            try: os.remove(tmp_image.name)
            except: pass
            return jsonify({"error": "Invalid image"}), 400
        decoded_text = decode_img_data(img)
        try: os.remove(tmp_image.name)
        except: pass
        return jsonify({"decoded_text": decoded_text})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/audio/encode', methods=['POST'])
def audio_encode_endpoint():
    try:
        file = request.files['audio']
        secret_text = request.form.get('text', '')
        tmp_audio = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
        tmp_audio.close()
        file.save(tmp_audio.name)
        output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
        output_file.close()
        encode_aud_data(tmp_audio.name, secret_text, output_file.name)
        try: os.remove(tmp_audio.name)
        except: pass
        return send_file(output_file.name, as_attachment=True, download_name="stego_audio.wav")
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/audio/decode', methods=['POST'])
def audio_decode_endpoint():
    try:
        file = request.files['audio']
        tmp_audio = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
        tmp_audio.close()
        file.save(tmp_audio.name)
        decoded_text = decode_aud_data(tmp_audio.name)
        try: os.remove(tmp_audio.name)
        except: pass
        return jsonify({"decoded_text": decoded_text})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/video/encode', methods=['POST'])
def video_encode_endpoint():
    try:
        video_file = request.files['video']
        secret_text = request.form.get('text', '')
        key = request.form.get('key', 'defaultkey')
        frame_number = int(request.form.get('frame_number', 1))

        tmp_video = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
        tmp_video.close()
        video_file.save(tmp_video.name)

        cap = cv2.VideoCapture(tmp_video.name)
        if not cap.isOpened():
            try: os.remove(tmp_video.name)
            except: pass
            return jsonify({"error": "Cannot open video file"}), 400

        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if total_frames <= 0:
            try: os.remove(tmp_video.name)
            except: pass
            return jsonify({"error": "Invalid/empty video"}), 400
        if frame_number < 1 or frame_number > total_frames:
            try: os.remove(tmp_video.name)
            except: pass
            return jsonify({"error": f"Frame number must be between 1 and {total_frames}"}), 400

        # Prefer lossless container/codec: try FFV1 in .avi
        out_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".avi")
        out_tmp.close()
        out_file = out_tmp.name
        
        fourcc = cv2.VideoWriter_fourcc(*'FFV1')
        writer = cv2.VideoWriter(out_file, fourcc, fps, (width, height))

        # If that didn't open (FFV1 not available), fallback to MJPG but warn (MJPG is lossy)
        used_lossless = True
        if not writer.isOpened():
            fourcc = cv2.VideoWriter_fourcc(*'MJPG')
            writer = cv2.VideoWriter(out_file, fourcc, fps, (width, height))
            used_lossless = False

        current_frame = 0
        ok, frame = cap.read()
        while ok:
            current_frame += 1
            if current_frame == frame_number:
                try:
                    frame = embed_frame(frame, secret_text, key)
                except ValueError as ve:
                    cap.release()
                    writer.release()
                    # delete partial file
                    try: os.remove(out_file)
                    except: pass
                    try: os.remove(tmp_video.name)
                    except: pass
                    return jsonify({"error": str(ve)}), 400
            writer.write(frame)
            ok, frame = cap.read()

        cap.release()
        writer.release()
        
        try: os.remove(tmp_video.name)
        except: pass

        resp = send_file(out_file, as_attachment=True, download_name=("stego_video.avi" if used_lossless else "stego_video_fallback.avi"))
        # include header so frontend can know if codec was lossy fallback
        resp.headers['X-StegaVault-Lossless'] = '1' if used_lossless else '0'
        if not used_lossless:
            # also warn in body (frontend should show toast)
            # NOTE: send_file with custom headers still returns file; we include header above
            pass
        return resp

    except Exception as e:
        return jsonify({"error": f"Video encoding error: {str(e)}"}), 500

@app.route('/video/decode', methods=['POST'])
def video_decode_endpoint():
    try:
        video_file = request.files['video']
        key = request.form.get('key', 'defaultkey')
        frame_number = int(request.form.get('frame_number', 1))

        tmp_video = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
        tmp_video.close()
        video_file.save(tmp_video.name)

        cap = cv2.VideoCapture(tmp_video.name)
        if not cap.isOpened():
            try: os.remove(tmp_video.name)
            except: pass
            return jsonify({"error": "Cannot open video file"}), 400

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if frame_number < 1 or frame_number > total_frames:
            cap.release()
            try: os.remove(tmp_video.name)
            except: pass
            return jsonify({"error": f"Frame number must be between 1 and {total_frames}"}), 400

        current_frame = 0
        extracted_text = ""
        while True:
            success, frame = cap.read()
            if not success:
                break
            current_frame += 1
            if current_frame == frame_number:
                extracted_text = extract_frame(frame, key)
                break

        cap.release()
        try: os.remove(tmp_video.name)
        except: pass

        if not extracted_text:
            return jsonify({"error": "No data found"}), 400

        return jsonify({"decoded_text": extracted_text})
    except Exception as e:
        return jsonify({"error": f"Video decoding error: {str(e)}"}), 500

# ------------------ DETECTION HELPERS ------------------ #
def detect_txt_stego(file_path):
    # Check for ZWC
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()
        for char in content:
            if char in ZWC_reverse:
                # Found at least one ZWC, likely stego
                # To be more robust, we could check for the termination marker pattern
                # But simple presence is a strong indicator for this algorithm
                return True
    return False

def detect_img_stego(img):
    data_binary = ""
    # Process only enough to find the marker? 
    # Or strict check? The existing decode runs sequentially.
    # To be safe, we use a similar logic to decode but return boolean.
    
    # Flattening logic from decode_img_data
    # Optimization: processing line by line instead of full flatten first
    # might save memory but let's stick to the known working logic from decode_img_data
    # but abort early if we find the marker.
    
    for row in img:
        for pixel in row:
            for k in range(3):
                data_binary += str(pixel[k] & 1)
                
                # Check every byte (8 bits)
                if len(data_binary) >= 40: # minimal length (5 chars * 8 bits = 40)
                     if len(data_binary) % 8 == 0:
                        # Extract the string ending
                        # Only need to check the last few bytes newly added
                        pass

    # Re-using strict logic from decode_img_data basically:
    all_bytes = [data_binary[i:i+8] for i in range(0, len(data_binary), 8)]
    decoded_data = ""
    for byte in all_bytes:
        try:
            decoded_data += chr(int(byte, 2))
            if decoded_data.endswith("*^*^*"):
                return True
        except:
            continue
    return False

def detect_aud_stego(audio_path):
    song = wave.open(audio_path, mode='rb')
    frames = song.readframes(song.getnframes())
    frame_bytes = bytearray(list(frames))
    song.close()
    
    extracted = ''.join([str(b & 1) for b in frame_bytes])
    all_bytes = [extracted[i:i+8] for i in range(0, len(extracted), 8)]
    decoded_data = ""
    for byte in all_bytes:
        try:
            decoded_data += chr(int(byte, 2))
            if decoded_data.endswith("*^*^*"):
                return True
        except:
            continue
    return False

def detect_vid_stego(video_path):
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return False

    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    # Checking every frame might be slow for large videos.
    # But "drag and drop" implies we should check.
    # We'll check first 50 frames, or maybe every Nth frame?
    # The encoding allows picking a specific frame. User could have picked frame 100.
    # If we want to be thorough, we must check all.
    # Let's check all but break early.
    
    while True:
        success, frame = cap.read()
        if not success:
            break
        
        # Check this frame
        if detect_img_stego(frame): # Reusing image detection logic for frame
             cap.release()
             return True

    cap.release()
    return False

@app.route('/detect', methods=['POST'])
def detect_steganography():
    try:
        file = None
        for key in request.files:
            file = request.files[key]
            break
        
        if not file:
            return jsonify({"error": "No file provided"}), 400

        filename = (file.filename or "").lower()
        is_stego = False
        msg = "No hidden data detected."

        if filename.endswith(".txt"):
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
            tmp.close()
            file.save(tmp.name)
            if detect_txt_stego(tmp.name):
                is_stego = True
                msg = "Hidden data detected in text file!"
            os.remove(tmp.name)
            
        elif filename.endswith((".png", ".jpg", ".jpeg")):
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
            tmp.close()
            file.save(tmp.name)
            img = cv2.imread(tmp.name)
            if img is not None:
                if detect_img_stego(img):
                    is_stego = True
                    msg = "Hidden data detected in image!"
            os.remove(tmp.name)

        elif filename.endswith(".wav"):
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
            tmp.close()
            file.save(tmp.name)
            if detect_aud_stego(tmp.name):
                is_stego = True
                msg = "Hidden data detected in audio file!"
            os.remove(tmp.name)

        elif filename.endswith((".mp4", ".avi", ".mov")):
             tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
             tmp.close()
             file.save(tmp.name)
             if detect_vid_stego(tmp.name):
                 is_stego = True
                 msg = "Hidden data detected in video file!"
             os.remove(tmp.name)
        else:
            return jsonify({"error": "Unsupported file type"}), 400

        return jsonify({
            "detected": is_stego,
            "message": msg
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------ ANALYZE ------------------ #
@app.route('/analyze', methods=['POST'])
def analyze_cover():
    try:
        file = None
        filename = None
        secret_text = request.form.get('text', '')

        for field_name in ['file', 'image', 'audio', 'video']:
            if field_name in request.files:
                file = request.files[field_name]
                break

        if not file:
            return jsonify({"error": "No file provided"}), 400

        filename = (file.filename or "").lower()
        payload_bits = len(secret_text.encode('utf-8')) * 8

        # Helper to compute score based on utilization
        def compute_score(payload_bits, capacity_bits, format_multiplier=1.0):
            if capacity_bits <= 0:
                return 0, 100  # No capacity, score 0, utilization 100%
            
            utilization = payload_bits / capacity_bits
            
            # Score is higher when utilization is lower (more space available)
            # We want a score of 100 when utilization is 0%, and 0 when utilization is 100%+
            base_score = max(0, 100 - (utilization * 100))
            
            # Apply format multiplier
            score = min(100, base_score * format_multiplier)
            
            return round(score), min(100, utilization * 100)

        # ---------------- Image ----------------
        if filename.endswith((".png", ".jpg", ".jpeg")):
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
            tmp.close()
            file.save(tmp.name)
            img = cv2.imread(tmp.name)
            if img is None:
                tmp_fn = tmp.name
                try: os.remove(tmp_fn)
                except: pass
                return jsonify({"error": "Could not read image file"}), 400

            h, w, _ = img.shape
            # clean up temp file immediately? No, analyze might need it? 
            # Actually analyze just reads img. So we can remove it.
            # But wait, logic continues. 
            # We should probably remove it at the end of the block or use try/finally.
            # For now just closing it prevents the lock.
            try: os.remove(tmp.name)
            except: pass

            capacity_bits = h * w * 3  # 3 bits per pixel (1 per channel)
            format_info = "image/png" if filename.endswith(".png") else "image/jpeg"
            safe_format = filename.endswith(".png")

            # PNG gets a bonus, JPEG gets a penalty
            mult = 1.2 if safe_format else 0.8
            score, util_percent = compute_score(payload_bits, capacity_bits, mult)
            fits = payload_bits <= capacity_bits

            reasons = [
                f"Image dimensions: {w}x{h} pixels",
                f"Total capacity: {capacity_bits} bits",
                f"Payload size: {payload_bits} bits",
                f"Utilization: {util_percent:.1f}%"
            ]
            
            if safe_format:
                reasons.append("✓ Lossless PNG format is ideal for steganography")
            else:
                reasons.append("⚠ JPEG is lossy and may corrupt hidden data")

            return jsonify({
                "score": score,
                "fits": fits,
                "metrics": {
                    "payload_bits": payload_bits,
                    "capacity_bits": capacity_bits,
                    "format": format_info,
                    "utilization_percent": util_percent
                },
                "reasons": reasons,
                "advice": "Use PNG format for better results" if not safe_format else "Good cover choice"
            })

        # ---------------- Audio (WAV) ----------------
        elif filename.endswith(".wav"):
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
            tmp.close()
            file.save(tmp.name)
            try:
                song = wave.open(tmp.name, 'rb')
                frames = song.getnframes()
                channels = song.getnchannels()
                sample_width = song.getsampwidth()
                song.close()
                try: os.remove(tmp.name)
                except: pass
                
                # Calculate capacity more accurately
                capacity_bits = frames * channels * 8  # 1 bit per sample
                format_info = "audio/wav"
                
                # Audio gets a moderate bonus
                mult = 1.1
                score, util_percent = compute_score(payload_bits, capacity_bits, mult)
                fits = payload_bits <= capacity_bits
                
                reasons = [
                    f"Audio frames: {frames}",
                    f"Channels: {channels}",
                    f"Sample width: {sample_width} bytes",
                    f"Total capacity: {capacity_bits} bits",
                    f"Payload size: {payload_bits} bits",
                    f"Utilization: {util_percent:.1f}%",
                    "✓ WAV format is good for audio steganography"
                ]
                
                return jsonify({
                    "score": score,
                    "fits": fits,
                    "metrics": {
                        "payload_bits": payload_bits,
                        "capacity_bits": capacity_bits,
                        "format": format_info,
                        "utilization_percent": util_percent
                    },
                    "reasons": reasons,
                    "advice": "Payload fits well" if fits else "Payload too large for this audio file"
                })
            except Exception as e:
                return jsonify({"error": f"Invalid audio file: {str(e)}"}), 400

        # ---------------- Text ----------------
        elif filename.endswith(".txt"):
            content = file.read().decode("utf-8")
            words = content.split()
            
            # 12 bits per word (6 ZWC characters, each representing 2 bits)
            capacity_bits = len(words) * 12
            format_info = "text/plain"
            
            # Text gets a neutral multiplier
            mult = 1.0
            score, util_percent = compute_score(payload_bits, capacity_bits, mult)
            fits = payload_bits <= capacity_bits
            
            reasons = [
                f"Words in cover: {len(words)}",
                f"Total capacity: {capacity_bits} bits",
                f"Payload size: {payload_bits} bits",
                f"Utilization: {util_percent:.1f}%",
                "✓ Text steganography uses zero-width characters"
            ]
            
            return jsonify({
                "score": score,
                "fits": fits,
                "metrics": {
                    "payload_bits": payload_bits,
                    "capacity_bits": capacity_bits,
                    "format": format_info,
                    "utilization_percent": util_percent
                },
                "reasons": reasons,
                "advice": "Add more text to increase capacity" if not fits else "Good text cover"
            })

        # ---------------- Video ----------------
        elif filename.endswith((".mp4", ".avi", ".mov")):
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4")
            tmp.close()
            file.save(tmp.name)

            cap = cv2.VideoCapture(tmp.name)
            if not cap.isOpened():
                try: os.remove(tmp.name)
                except: pass
                return jsonify({"error": "Could not open video file"}), 400

            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

            # Estimate capacity based on 10 frames
            frame_capacity = width * height * 3  # 3 bits per pixel
            capacity_bits = frame_capacity * 10  # Use 10 frames
            
            format_info = "video/mp4"
            
            # Video gets a small penalty due to complexity
            mult = 0.9
            score, util_percent = compute_score(payload_bits, capacity_bits, mult)
            fits = payload_bits <= capacity_bits
            
            cap.release()
            try: os.remove(tmp.name)
            except: pass
            
            reasons = [
                f"Video dimensions: {width}x{height}",
                f"Frame count: {frame_count}",
                f"Estimated capacity: {capacity_bits} bits",
                f"Payload size: {payload_bits} bits",
                f"Utilization: {util_percent:.1f}%",
                "✓ Video offers good hiding capacity"
            ]
            
            return jsonify({
                "score": score,
                "fits": fits,
                "metrics": {
                    "payload_bits": payload_bits,
                    "capacity_bits": capacity_bits,
                    "format": format_info,
                    "utilization_percent": util_percent
                },
                "reasons": reasons,
                "advice": "Video has plenty of space for your payload" if fits else "Payload too large for video"
            })

        else:
            return jsonify({"error": "Unsupported file type"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ------------------ MULTILAYER STEGANOGRAPHY & VIDEO 2-BIT LSB ------------------ #
import zlib

HEADER = b'<<START>>'
FOOTER = b'<<END>>'

def get_file_type(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in ['.txt', '.csv', '.json', '.md']: return 'text'
    if ext in ['.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tif', '.tiff', '.webp']: return 'image'
    if ext in ['.wav', '.mp3', '.flac', '.aac', '.ogg', '.m4a']: return 'audio'
    if ext in ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.flv', '.wmv']: return 'video'
    return 'unknown'

def encode_video_multiframe(video_path, secret_data_str, output_path):
    print(f"🎬 Starting Video Encode (2-Bit LSB - VECTORIZED)...")
    
    # 1. Convert secret string to bytes
    secret_bytes = secret_data_str.encode('utf-8')
    
    # 2. Compress data
    compressed_data = zlib.compress(secret_bytes)
    print(f"   Original: {len(secret_bytes)} bytes -> Compressed: {len(compressed_data)} bytes")
    
    # 3. Add Header/Footer
    # HEADER = 9 bytes, FOOTER = 7 bytes
    payload = HEADER + compressed_data + FOOTER
    
    cap = cv2.VideoCapture(video_path)
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    
    if total_frames <= 0:
        # Fallback if frame count is missing
        print("   Warning: Total frames unknown. Proceeding without strict capacity check.")
        total_frames = 999999
        
    # Capacity: 1 frame = height * width * 3 channels
    # 2 bits per channel => 1 byte per 4 channels
    # Bytes per frame = (H * W * 3) / 4
    bytes_per_frame = (height * width * 3) // 4
    max_bytes = bytes_per_frame * total_frames
    
    if len(payload) > max_bytes:
        cap.release()
        raise ValueError(f"Video file too small! Needed {len(payload)} bytes, capacity approx {max_bytes} bytes.")

    # Use FFV1 (Lossless)
    fourcc = cv2.VideoWriter_fourcc(*'FFV1') 
    out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

    # VECTORIZATION PREP
    # Convert payload bytes to numpy array of 2-bit values
    # 1 byte = 8 bits = 4 chunks of 2-bits
    # [b7 b6], [b5 b4], [b3 b2], [b1 b0]
    
    payload_arr = np.frombuffer(payload, dtype=np.uint8)
    
    # Unpack to bits
    bits = np.unpackbits(payload_arr) # shape (N*8,)
    
    # Reshape to (-1, 2) to get pairs of bits
    # Then convert pairs to values 0-3
    # val = bit0 * 2 + bit1
    pairs = bits.reshape(-1, 2)
    values = (pairs[:, 0] << 1) | pairs[:, 1]
    values = values.astype(np.uint8)
    
    total_vals = len(values)
    val_idx = 0
    
    frame_capacity = height * width * 3 # channels per frame
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret: break
        
        if val_idx < total_vals:
            # Flatten frame to 1D array of pixels
            flat = frame.reshape(-1)
            
            # Determine how many values we can write in this frame
            remaining_vals = total_vals - val_idx
            write_count = min(remaining_vals, len(flat))
            
            # Get the chunk of payload values to write
            chunk_vals = values[val_idx : val_idx + write_count]
            
            # VECTORIZED WRITE
            # Clear LSBs (last 2 bits) -> & 0xFC (11111100)
            # OR with values
            
            # We operate only on the slice required
            target_slice = flat[:write_count]
            
            target_slice[:] = (target_slice & 0xFC) | chunk_vals
            
            # Update flat array
            flat[:write_count] = target_slice
            
            # Update counters
            val_idx += write_count
            
            # Reshape back to frame
            frame = flat.reshape((height, width, 3))
            
        out.write(frame)
        
    cap.release()
    out.release()
    print("🎬 Video Encode Complete.")

def decode_video_multiframe(video_path):
    print("🎬 Starting Video Decode (2-Bit LSB - FAST)...")
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened(): return ""
    
    # Precompute patterns
    header_bits = ''.join([format(b, '08b') for b in HEADER])
    footer_bits = ''.join([format(b, '08b') for b in FOOTER])
    
    # We will search in BYTE stream directly for speed
    
    # Accumulate bytes
    all_bytes = bytearray()
    
    try:
        max_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        if max_frames > 0:
            print(f"   Processing {max_frames} frames...")
        else:
            print("   Processing frames (count unknown)...")
    except:
        pass
    
    import numpy as np # Ensure numpy is imported
    
    frame_idx = 0
    found_footer = False
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret: break
        
        flat = frame.flatten()
        msg_len = flat.size
        
        # Crop to multiple of 4 to form full bytes
        # 4 pixels -> 1 byte
        valid_len = (msg_len // 4) * 4
        flat = flat[:valid_len]
        
        # Extract LSBs (2 bits)
        # We need to vectorized this:
        # P0(bits 7,6), P1(bits 5,4), P2(bits 3,2), P3(bits 1,0)
        # Actually in encoding: 
        #   chunk = payload_bits[bit_idx:bit_idx+2]
        #   val = int(chunk, 2)
        #   flat[i] = ... | val
        # So P0 has the FIRST 2 bits of the byte.
        # Thus: Byte = (P0 & 3) << 6 | (P1 & 3) << 4 | (P2 & 3) << 2 | (P3 & 3)
        
        # Reshape to (N, 4)
        packed = flat.reshape(-1, 4)
        
        # Extract 2 bits from each pixel
        p0 = packed[:, 0] & 3
        p1 = packed[:, 1] & 3
        p2 = packed[:, 2] & 3
        p3 = packed[:, 3] & 3
        
        # Reconstruct bytes
        # Using numpy vectorized operations (orders of magnitude faster)
        bytes_chunk = (p0 << 6) | (p1 << 4) | (p2 << 2) | p3
        
        # Append to buffer
        new_bytes = bytes_chunk.astype(np.uint8).tobytes()
        all_bytes.extend(new_bytes)
        
        # Aggressive Optimization: Check for footer efficiently
        # Instead of scanning the entire all_bytes (O(N^2)), scan only the recent chunk + overlap
        overlap = len(FOOTER) + 1
        search_window = all_bytes[-(len(new_bytes) + overlap):]
        
        if FOOTER in search_window:
            print("   Found Footer! Stopping early.")
            found_footer = True
            break
                
        frame_idx += 1
        
    cap.release()
    
    # Now valid_data is a bytes object
    # Find HEADER
    try:
        start_idx = all_bytes.find(HEADER)
        if start_idx == -1: 
            print("   Header not found.")
            return ""
            
        data_start = start_idx + len(HEADER)
        
        end_idx = all_bytes.find(FOOTER, data_start)
        if end_idx == -1:
            print("   Footer not found (incomplete or corrupted).")
            return ""
            
        compressed_data = all_bytes[data_start:end_idx]
        
        # Decompress
        print(f"   Decompressing {len(compressed_data)} bytes...")
        decompressed = zlib.decompress(bytes(compressed_data))
        return decompressed.decode('utf-8')
        
    except Exception as e:
        print(f"   Video Decode Error: {e}")
        return ""


def generic_encode(cover_path, secret_b64, output_path, key=None):
    ftype = get_file_type(cover_path)
    
    # Encrypt first
    encrypted_data = encryption(secret_b64, key)
    
    if ftype == 'text':
        # (Existing text logic, simplified for restore)
        txt_encode(encrypted_data, cover_path, output_path)
    elif ftype == 'image':
        img = cv2.imread(cover_path)
        encode_img_data(img, encrypted_data, output_path)
    elif ftype == 'audio':
        # (Assume encode_aud_data exists or we need to restore it too? 
        # The previous read showed txt_encode, encode_img_data, but NOT audio)
        # We need to restore audio functions too if they are missing!
        # For now, let's assume they might be missing.
        # But user undid edits to app.py. Multilayer added audio/video logic.
        # Basic app.py usually has audio support. Let's check.
        # Read file showed 'import wave' so audio support is likely there.
        # But I better wrap this safe.
        try:
             # Try calling existing function
             encode_aud_data(cover_path, encrypted_data, output_path)
        except NameError:
             # Fallback implementation if missing
             song = wave.open(cover_path, mode='rb')
             frame_bytes = bytearray(list(song.readframes(song.getnframes())))
             data = encrypted_data + '*^*^*'
             bits = ''.join([format(ord(i), '08b') for i in data])
             
             for i, bit in enumerate(bits):
                frame_bytes[i] = (frame_bytes[i] & 254) | int(bit)
             
             with wave.open(output_path, 'wb') as fd:
                fd.setparams(song.getparams())
                fd.writeframes(frame_bytes)
             song.close()

    elif ftype == 'video':
        encode_video_multiframe(cover_path, encrypted_data, output_path)
    else:
        # Better error message
        raise ValueError(f"Unsupported file type: {get_file_type(cover_path)} (ext: {os.path.splitext(cover_path)[1]})")

def generic_decode(stego_path, key=None):
    ftype = get_file_type(stego_path)
    encrypted_data = ""
    
    if ftype == 'text':
        encrypted_data = decode_txt_data(stego_path)
    elif ftype == 'image':
        img = cv2.imread(stego_path)
        result = decode_img_data(img)
        # Extract until terminator
        if '*^*^*' in result:
             encrypted_data = result.split('*^*^*')[0]
        else:
             encrypted_data = result # Try full?
    elif ftype == 'audio':
        try:
            encrypted_data = decode_aud_data(stego_path) 
        except NameError:
            song = wave.open(stego_path, mode='rb')
            frame_bytes = bytearray(list(song.readframes(song.getnframes())))
            bits = [str(frame_bytes[i] & 1) for i in range(len(frame_bytes))]
            bit_string = "".join(bits)
            chars = []
            for i in range(0, len(bit_string), 8):
                byte = bit_string[i:i+8]
                try: chars.append(chr(int(byte, 2)))
                except: break
            full_str = "".join(chars)
            if '*^*^*' in full_str:
                encrypted_data = full_str.split('*^*^*')[0]
            song.close()
            
    elif ftype == 'video':
        encrypted_data = decode_video_multiframe(stego_path)
    
    if not encrypted_data: return ""
    return decryption(encrypted_data, key)


@app.route('/multilayer/encode', methods=['POST'])
def multilayer_encode():
    cleanup_files = []
    try:
        # Inputs
        secret_text = request.form.get('secret_text')
        secret_file = request.files.get('secret_file')
        key = request.form.get('key', 'default-key')

        # Collect Layers Dynamically
        layers = []
        i = 0
        while True:
            # Check for both 'layer_X' (dynamic) and legacy 'file1'/'file2' (fallback)
            f = request.files.get(f'layer_{i}')
            
            # Legacy mapping for first two layers if dynamic names aren't used
            if not f and i == 0: f = request.files.get('file1')
            if not f and i == 1: f = request.files.get('file2')
            
            # If still found valid file...
            if f and f.filename:
                layers.append(f)
                i += 1
            else:
                # Stop if we hit a gap or run out
                # But careful about legacy: file2 might be missing but file1 present.
                # If i=0 (file1) found, i=1 (file2) missing, we stop.
                # If i=0 (file1) missing, we stop immediately.
                if i > 1 and not request.files.get(f'layer_{i}'): break
                if i == 0 and not request.files.get('file1') and not request.files.get('layer_0'): break
                if i == 1 and not request.files.get('file2') and not request.files.get('layer_1'): break
                # If we are checking legacy and didn't find it, continue logic inside loop doesn't help. 
                # Let's clean this up:
                break
        
        if not layers:
             return jsonify({"error": "At least one carrier file is required"}), 400

        # Prepare Secret Data (Initial Payload)
        current_payload = ""
        if secret_text:
            current_payload = secret_text
        elif secret_file:
            file_bytes = secret_file.read()
            current_payload = base64.b64encode(file_bytes).decode('utf-8')
        else:
            return jsonify({"error": "No secret provided (text or file)"}), 400

        # --- DYNAMIC LAYERING LOOP ---
        final_file_path = None
        
        for idx, carrier_file in enumerate(layers):
            print(f"DEBUG: Processing Layer {idx+1}/{len(layers)} - Carrier: {carrier_file.filename}")
            
            # 1. Save Carrier File Temp
            ext = os.path.splitext(carrier_file.filename)[1].lower()
            if not ext: ext = '.png'
            
            tmp_carrier = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
            tmp_carrier.close()
            carrier_file.save(tmp_carrier.name)
            cleanup_files.append(tmp_carrier.name)
            
            # 2. Determine Output Extension
            ftype = get_file_type(carrier_file.filename)
            out_ext = ext
            if ftype == 'video': out_ext = '.avi'
            elif ftype == 'audio': out_ext = '.wav'
            elif ftype == 'image': out_ext = '.png'
            if ext == '.txt': out_ext = '.txt'

            # 3. Create Temp Output File
            tmp_out = tempfile.NamedTemporaryFile(delete=False, suffix=out_ext)
            tmp_out.close()
            cleanup_files.append(tmp_out.name)
            
            # 4. Encode (Current Payload -> Hidden in Carrier -> Output)
            generic_encode(tmp_carrier.name, current_payload, tmp_out.name, key)
            
            # 5. Prepare Payload for NEXT Layer
            # If this is not the last layer, the Output of this step becomes the Payload of the next.
            if idx < len(layers) - 1:
                with open(tmp_out.name, "rb") as f_read:
                    layer_bytes = f_read.read()
                # Determine next payload (File -> Base64 String)
                current_payload = base64.b64encode(layer_bytes).decode('utf-8')
                
                # We can verify size here? If it gets too big, might fail.
                # But for now we proceed.
            else:
                final_file_path = tmp_out.name
                final_ext = out_ext

        # Return Final Result
        if final_file_path:
             return send_file(final_file_path, as_attachment=True, download_name=f"multilayer_result{final_ext}")
        else:
             return jsonify({"error": "Encoding failed unexpectedly"}), 500

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 400
    finally:
        # Cleanup Inputs (careful not to delete the final result we are sending)
        for f in cleanup_files:
            if f != final_file_path: # Don't delete what we are sending! 
                # Flask send_file doesn't lock it? Actually it needs it open/available.
                # Standard pattern: Cleaner waits or we rely on OS temp cleaner.
                # But to be safe, we usually delete only inputs.
                try: os.remove(f)
                except: pass
                
        # NOTE: final_file_path will be leftover. In production, use a scheduled cleaner.
            if f != final_file_path: 
                try: os.remove(f)
                except: pass

@app.route('/multilayer/decode', methods=['POST'])
def multilayer_decode():
    try:
        print("DEBUG: multilayer_decode called")
        
        f = request.files.get('file')
        key = request.form.get('key', 'default-key')
        
        print(f"DEBUG: File received: {f is not None}")
        if f:
            print(f"DEBUG: Filename: {f.filename}")
            print(f"DEBUG: Content type: {f.content_type}")
        print(f"DEBUG: Key: {key}")
        
        if not f:
            print("DEBUG: No file in request")
            return jsonify({"error": "No file provided"}), 400
            
        # Secure filename handling
        original_ext = os.path.splitext(f.filename)[1].lower()
        print(f"DEBUG: Original extension: {original_ext}")
        if not original_ext:
            original_ext = ".tmp"

        tmp_in = tempfile.NamedTemporaryFile(delete=False, suffix=original_ext)
        tmp_in.close()
        f.save(tmp_in.name)
        
        print(f"DEBUG: Saved to temp file: {tmp_in.name}")

        # CHECK FOR EMPTY FILE (Prevents crash on 0KB input)
        file_size = os.path.getsize(tmp_in.name)
        print(f"DEBUG: File size: {file_size} bytes")
        if file_size == 0:
            os.remove(tmp_in.name)
            return jsonify({"error": "Uploaded file is empty. Please verify your file."}), 400
        
        # Decode Layer
        print("DEBUG: Starting generic_decode")
        decrypted = generic_decode(tmp_in.name, key)
        os.remove(tmp_in.name)
        
        print(f"DEBUG: Decrypted result length: {len(decrypted) if decrypted else 0}")

        if not decrypted:
            print("DEBUG: No decrypted data found")
            return jsonify({"error": "No hidden data found"}), 400

        # Attempt to detect if 'decrypted' is a Base64 encoded file
        # Common issue: Raw Base64 string is returned instead of the binary file.
        
        # 1. Clean the string
        if isinstance(decrypted, bytes):
            decrypted_str = decrypted.decode('utf-8', errors='ignore')
        else:
            decrypted_str = decrypted
            
        # Keep original for fallback
        original_decrypted = decrypted_str 

        # Remove whitespace/newlines for reliable Base64 decoding
        if decrypted_str:
             decrypted_str = "".join(decrypted_str.split())

        is_file = False
        file_bytes = None
        out_name = "extracted.txt"
        mime = "text/plain"

        try:
            # Use a temporary string for padding checks so we don't corrupt the original
            candidate_str = decrypted_str
            
            # Fix padding if missing
            missing_padding = len(candidate_str) % 4
            if missing_padding:
                candidate_str += '=' * (4 - missing_padding)

            # Try Base64 Decode
            decoded_candidate = base64.b64decode(candidate_str, validate=True)

            # Check Magic Numbers
            if decoded_candidate.startswith(b'RIFF') and b'WAVE' in decoded_candidate[:16]:
                is_file = True
                out_name = "extracted_audio.wav"
                mime = "audio/wav"
            elif decoded_candidate.startswith(b'RIFF') and b'AVI ' in decoded_candidate[:16]:
                is_file = True
                out_name = "extracted_video.avi"
                mime = "video/x-msvideo"
            elif decoded_candidate.startswith(b'\x89PNG'):
                is_file = True
                out_name = "extracted_image.png"
                mime = "image/png"
            elif decoded_candidate.startswith(b'\xFF\xD8\xFF'):
                is_file = True
                out_name = "extracted_image.jpg"
                mime = "image/jpeg"
            else:
                # If valid Base64 but no binary header
                # We assume it is a Generic File (likely Text) that was hidden.
                # We always trust the Base64 decode result.
                is_file = True
                out_name = "secret_file.txt"
                mime = "application/octet-stream"
            
            if is_file:
                file_bytes = decoded_candidate
                # Recursive decode removed as per user request to get the raw file.

        except Exception as e:
            # Not a valid base64 file, treat as text
            pass

        if is_file and file_bytes:
            tmp_out = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(out_name)[1])
            tmp_out.close()
            with open(tmp_out.name, "wb") as fo:
                fo.write(file_bytes)
            
            return send_file(tmp_out.name, as_attachment=True, download_name=out_name, mimetype=mime)
        else:
            # Return text directly
            # Use original_decrypted to ensure no accidental whitespace removal 
            # or padding addition if it was just plain text all along.
            return original_decrypted, 200, {'Content-Type': 'text/plain'}

    except Exception as e:
        print(f"DEBUG: Exception in multilayer_decode: {e}")
        print(f"DEBUG: Exception type: {type(e)}")
        import traceback
        print(f"DEBUG: Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 400

# ------------------ HOME ------------------ #
@app.route('/')
def home():
    return jsonify({
        "message": "StegaVault API is running",
        "endpoints": {
            "text_encode": "/text/encode",
            "text_decode": "/text/decode",
            "image_encode": "/image/encode",
            "image_decode": "/image/decode",
            "audio_encode": "/audio/encode",
            "audio_decode": "/audio/decode",
            "video_encode": "/video/encode",
            "video_decode": "/video/decode",
            "analyze": "/analyze"
        }
    })

if __name__ == '__main__':
    # debug True is helpful during dev; set to False in production
    app.run(debug=True, host="0.0.0.0", port=5000)
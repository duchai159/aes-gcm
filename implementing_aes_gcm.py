import math
import os
from implementing_aes import aes_encryption
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk


def xor_bytes(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes([a ^ b for (a, b) in zip(bytes_a, bytes_b)])


def MUL(X_bytes, Y_bytes):
    """
    Thực hiện phép nhân trong trường GF(2^128), sử dụng thuật toán nhân đa thức.
    Hàm này thực hiện nhân hai chuỗi byte X và Y theo mô hình trường Galois GF(2^128), 
    sử dụng phép toán XOR, dịch trái/phải, và hằng số R định nghĩa cho thuật toán.

    Parameters:
    - X_bytes: Một chuỗi byte đại diện cho số X trong GF(2^128).
    - Y_bytes: Một chuỗi byte đại diện cho số Y trong GF(2^128).

    Returns:
    - Kết quả của phép nhân, trả về dưới dạng chuỗi byte dài 16 byte.
    """
    # Chuyển đổi X và Y từ dạng bytes thành số nguyên lớn
    X = int.from_bytes(X_bytes, 'big')
    Y = int.from_bytes(Y_bytes, 'big')

    # Hằng số R được định nghĩa trong thuật toán
    R = 0xe1 << 120

    # Bước 1: Biểu diễn X dưới dạng dãy bit
    x = [1 if X & (1 << i) else 0 for i in range(127, -1, -1)]

    # Bước 2 và 3: Thực hiện phép nhân trong trường Galois với các phép toán XOR và dịch bit
    Z_i = 0  # Giá trị kết quả
    V_i = Y  # Bắt đầu với V = Y
    for i in range(128):
        # Nếu x[i] = 0, không thay đổi Z_i, ngược lại thực hiện phép XOR
        if x[i] == 0:
            Z_i_1 = Z_i
        else:
            Z_i_1 = Z_i ^ V_i

        # Dịch V_i sang phải, nếu V_i là số lẻ thì XOR thêm với hằng số R
        if V_i % 2 == 0:
            V_i_1 = V_i >> 1
        else:
            V_i_1 = (V_i >> 1) ^ R

        # Cập nhật Z_i và V_i cho vòng lặp tiếp theo
        Z_i = Z_i_1
        V_i = V_i_1

    # Bước 4: Chuyển kết quả Z_i về dạng chuỗi byte 16 byte và trả về
    return Z_i.to_bytes(16, 'big')



def GHASH(H, X):
    """
    Tính toán giá trị GHASH theo chuẩn GCM (Galois/Counter Mode).
    GHASH được sử dụng để tạo giá trị xác thực trong quá trình mã hóa hoặc giải mã.

    Parameters:
    - H: Chuỗi byte đại diện cho khóa hash (128-bit).
    - X: Chuỗi byte dữ liệu đầu vào, có độ dài bội số của 128 bit (16 byte).

    Returns:
    - Giá trị GHASH (128-bit) dưới dạng chuỗi byte.
    """

    # Ràng buộc: Độ dài của X phải là bội số của 128 bit (16 byte)
    m = len(X) // 16  # Tính số khối (blocks) trong X

    # Bước 1: Chia dữ liệu X thành các khối 16 byte
    X_blocks = [X[i*16:(i+1)*16] for i in range(m)]

    # Bước 2: Khởi tạo giá trị Y_0 là 16 byte 0
    Y_0 = b'\x00' * 16

    # Bước 3: Thực hiện tính toán GHASH trên từng khối
    Y_i_1 = Y_0  # Ban đầu Y_i_1 = Y_0
    for i in range(m):
        X_i = X_blocks[i]  # Lấy khối X_i
        # Tính Y_i = MUL(Y_i-1 XOR X_i, H), trong đó MUL là phép nhân GF(2^128)
        Y_i = MUL(xor_bytes(Y_i_1, X_i), H)
        Y_i_1 = Y_i  # Cập nhật Y_i_1 cho vòng lặp tiếp theo

    # Bước 4: Trả về kết quả cuối cùng Y_m
    return Y_i_1

def INC_32(Y_bytes):
    """
    Tăng giá trị bộ đếm 32-bit trong một chuỗi byte 16 byte.
    Hàm này dùng để xử lý giá trị bộ đếm trong chế độ CTR (Counter Mode) của AES.

    Parameters:
    - Y_bytes: Chuỗi byte đầu vào 16 byte, trong đó 4 byte cuối là bộ đếm 32-bit.

    Returns:
    - Chuỗi byte 16 byte với bộ đếm 32-bit được tăng lên 1.
    """
    # Chuyển đổi chuỗi byte 16 byte thành số nguyên lớn
    Y = int.from_bytes(Y_bytes, 'big')
    # Tăng giá trị 32-bit ở 4 byte cuối và giữ nguyên 12 byte đầu
    Y_inc = ((Y >> 32) << 32) ^ (((Y & 0xffffffff) + 1) & 0xffffffff)
    # Chuyển lại kết quả về dạng chuỗi byte 16 byte và trả về
    return Y_inc.to_bytes(16, 'big')


def GCTR(K, ICB, X):
    """
    Thực hiện GCTR (Galois Counter Mode Transformation) trong chuẩn GCM.
    Hàm này được sử dụng để mã hóa hoặc giải mã dữ liệu bằng chế độ CTR của AES.

    Parameters:
    - K: Khóa mã hóa (bytes), được sử dụng trong AES.
    - ICB: Chuỗi byte 16 byte (Initial Counter Block), là giá trị khởi tạo bộ đếm.
    - X: Chuỗi byte dữ liệu đầu vào cần xử lý (có thể có độ dài bất kỳ).

    Returns:
    - Chuỗi byte dữ liệu đầu ra sau khi áp dụng GCTR.
    """

    # Bước 1: Nếu X là chuỗi rỗng, trả về chuỗi rỗng
    if not X:
        return b''

    # Bước 2: Tính số khối 16 byte cần xử lý (n)
    n = math.ceil(len(X) / 16)

    # Bước 3: Chia X thành các khối 16 byte (X_blocks)
    X_blocks = [X[i*16:(i+1)*16] for i in range(n)]

    # Bước 4: Khởi tạo danh sách CB với phần tử đầu tiên là ICB
    CB = [ICB]

    # Bước 5: Tạo các giá trị Counter Block (CB) bằng cách tăng dần ICB
    for i in range(1, n):
        CB_i = INC_32(CB[i-1])  # Tăng giá trị Counter Block trước đó
        CB.append(CB_i)

    # Bước 6 và 7: Tính các khối Y (Y_blocks) bằng cách mã hóa CB và XOR với X_blocks
    Y_blocks = []
    for i in range(n):
        X_i = X_blocks[i]  # Lấy khối X hiện tại
        CB_i = CB[i]       # Lấy Counter Block tương ứng
        # XOR giữa X_i và AES(CB_i, K)
        Y_i = xor_bytes(X_i, aes_encryption(CB_i, K))
        Y_blocks.append(Y_i)

    # Bước 8: Nối tất cả các khối Y thành chuỗi byte hoàn chỉnh
    Y = b''.join(Y_blocks)

    # Bước 9: Trả về kết quả Y
    return Y


def aes_gcm_encrypt(P, K, IV, A, t):
    """
    Thực hiện mã hóa AES-GCM (AES-Galois/Counter Mode).

    Parameters:
    - P: Văn bản gốc (Plaintext) cần mã hóa (bytes).
    - K: Khóa mã hóa (bytes) dùng trong AES.
    - IV: Giá trị khởi tạo (Initialization Vector) (bytes).
    - A: Dữ liệu phụ (Additional Authenticated Data) không được mã hóa, nhưng cần xác thực (bytes).
    - t: Độ dài thẻ xác thực (Authentication Tag) tính theo bit.

    Returns:
    - C: Văn bản mã hóa (Ciphertext) (bytes).
    - T: Thẻ xác thực (Authentication Tag) (bytes).
    """

    # Bước 1: Tính giá trị H bằng cách mã hóa một chuỗi toàn 0 bằng AES với khóa K
    H = aes_encryption(b'\x00' * (128 // 8), K)

    # Bước 2: Tính J_0 (Counter Block ban đầu) dựa trên độ dài của IV
    len_IV = len(IV) * 8  # Độ dài IV tính theo bit
    if len_IV == 96:  # Trường hợp IV dài 96 bit (chuẩn)
        J_0 = IV + b'\x00\x00\x00\x01'  # Thêm bộ đếm 1 vào cuối
    else:  # Trường hợp IV có độ dài khác 96 bit
        s = 128 * math.ceil(len_IV / 128) - len_IV  # Padding để làm tròn đến bội số của 128
        O_s_64 = b'\x00' * ((s + 64) // 8)  # Chuỗi byte toàn 0 có độ dài phù hợp
        len_IV_64 = int.to_bytes(len_IV, 8, 'big')  # Độ dài IV được biểu diễn dưới dạng 64 bit
        J_0 = GHASH(H, IV + O_s_64 + len_IV_64)  # Tính J_0 bằng GHASH

    # Bước 3: Mã hóa văn bản gốc P bằng GCTR, sử dụng J_0 + 1 làm Counter Block
    C = GCTR(K, INC_32(J_0), P)

    # Bước 4: Tính các độ dài cần thiết
    len_C, len_A = len(C) * 8, len(A) * 8  # Độ dài của C và A tính theo bit
    u = 128 * math.ceil(len_C / 128) - len_C  # Padding cần thêm cho C
    v = 128 * math.ceil(len_A / 128) - len_A  # Padding cần thêm cho A

    # Bước 5: Chuẩn bị dữ liệu để tính giá trị S
    O_v = b'\x00' * (v // 8)  # Padding cho A
    O_u = b'\x00' * (u // 8)  # Padding cho C
    len_A_64 = int.to_bytes(len_A, 8, 'big')  # Độ dài của A dưới dạng 64 bit
    len_C_64 = int.to_bytes(len_C, 8, 'big')  # Độ dài của C dưới dạng 64 bit
    S = GHASH(H, A + O_v + C + O_u + len_A_64 + len_C_64)  # Tính giá trị hash S

    # Bước 6: Tính thẻ xác thực T bằng GCTR
    T = GCTR(K, J_0, S)[:t // 8]  # Cắt thẻ xác thực theo độ dài t (bit)

    # Bước 7: Trả về Ciphertext và Authentication Tag
    return C, T


def aes_gcm_decrypt(C, T, K, IV, A, t):
    """
    Giải mã ciphertext sử dụng thuật toán AES-GCM.

    Parameters:
    - C (bytes): Ciphertext cần giải mã.
    - T (bytes): Mã xác thực (authentication tag).
    - K (bytes): Khóa giải mã.
    - IV (bytes): Vector khởi tạo (Initialization Vector).
    - A (bytes): Dữ liệu bổ sung (Additional Authenticated Data - AAD), không được mã hóa nhưng cần xác thực.
    - t (int): Độ dài mã xác thực (tính bằng bit).

    Returns:
    - bytes: Plaintext nếu xác thực thành công.
    - Nếu xác thực thất bại, hàm sẽ ném ra ngoại lệ `ValueError`.
    """
   
    # Bước 1: Tính toán khóa băm H
    H = aes_encryption(b'\x00' * (128 // 8), K)

    # Bước 2: Tính toán giá trị khối đếm khởi tạo J_0
    len_IV = len(IV) * 8
    if len_IV == 96:  # IV có độ dài 96 bit
        J_0 = IV + b'\x00\x00\x00\x01'
    else:
        s = 128 * math.ceil(len_IV / 128) - len_IV
        O_s_64 = b'\x00' * ((s + 64) // 8)
        len_IV_64 = int.to_bytes(len_IV, 8, 'big')
        J_0 = GHASH(H, IV + O_s_64 + len_IV_64)

    # Bước 3: Tạo đầu vào cho hàm GHASH
    len_C, len_A = len(C) * 8, len(A) * 8  # Độ dài của C và A tính bằng bit
    u = 128 * math.ceil(len_C / 128) - len_C  # Padding cần thêm cho C
    v = 128 * math.ceil(len_A / 128) - len_A  # Padding cần thêm cho A
    O_v = b'\x00' * (v // 8)  # Padding cho A
    O_u = b'\x00' * (u // 8)  # Padding cho C
    len_A_64 = int.to_bytes(len_A, 8, 'big')  # Độ dài của A dưới dạng 64 bit
    len_C_64 = int.to_bytes(len_C, 8, 'big')  # Độ dài của C dưới dạng 64 bit
    S = GHASH(H, A + O_v + C + O_u + len_A_64 + len_C_64)  # Tính giá trị hash S

    # Bước 4: Tính toán lại mã xác thực
    T_computed = GCTR(K, J_0, S)[:t // 8]  # Lấy t bit đầu tiên của kết quả

    # Bước 5: Kiểm tra mã xác thực
    if T != T_computed:
        raise ValueError("Authentication failed: Tags do not match.")

    # Bước 6: Giải mã ciphertext
    P = GCTR(K, INC_32(J_0), C)

    # Bước 7: Trả về plaintext
    return P


def main():
    print("=== AES-GCM Encryption/Decryption Interface ===")

    while True:
        print("\nOptions:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        choice = input("Select an option (1/2/3): ")

        if choice == "1":
            plaintext = input("Enter plaintext: ").encode('utf-8')
            key = os.urandom(16)  # Generate a 128-bit random key
            iv = os.urandom(12)   # Generate a 96-bit random IV
            aad = input("Enter additional authenticated data (AAD): ").encode('utf-8')
            t_length = 128  # Authentication tag length in bits

            # Encrypt
            ciphertext, tag = aes_gcm_encrypt(plaintext, key, iv, aad, t_length)

            print("\nEncryption successful:")
            print(f"Ciphertext (hex): {ciphertext.hex()}")
            print(f"Authentication Tag (hex): {tag.hex()}")
            print(f"Key (hex): {key.hex()}")
            print(f"IV (hex): {iv.hex()}")

        elif choice == "2":
            ciphertext = bytes.fromhex(input("Enter ciphertext (hex): "))
            tag = bytes.fromhex(input("Enter authentication tag (hex): "))
            key = bytes.fromhex(input("Enter key (hex): "))
            iv = bytes.fromhex(input("Enter IV (hex): "))
            aad = input("Enter additional authenticated data (AAD): ").encode('utf-8')
            t_length = 128  # Authentication tag length in bits

            try:
                # Decrypt
                plaintext = aes_gcm_decrypt(ciphertext, tag, key, iv, aad, t_length)
                print("\nDecryption successful:")
                print(f"Plaintext: {plaintext.decode('utf-8')}")
            except ValueError as e:
                print(f"\nDecryption failed: {e}")

        elif choice == "3":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

# def aes_gcm_encrypt(plaintext, key, iv, aad, t_length):
#     # Placeholder for encryption logic
#     return b"ciphertext", b"tag"

# def aes_gcm_decrypt(ciphertext, tag, key, iv, aad, t_length):
#     # Placeholder for decryption logic
#     return b"plaintext"

# def encrypt_action(entry_plaintext, entry_aad, label_encrypt_result):
#     plaintext = entry_plaintext.get()
#     aad = entry_aad.get()

#     key = os.urandom(16)  # Generate a 128-bit random key
#     iv = os.urandom(12)   # Generate a 96-bit random IV
#     t_length = 128  # Authentication tag length in bits

#     ciphertext, tag = aes_gcm_encrypt(plaintext.encode('utf-8'), key, iv, aad.encode('utf-8'), t_length)

#     result = (
#         f"Ciphertext (hex): {ciphertext.hex()}\n"
#         f"Authentication Tag (hex): {tag.hex()}\n"
#         f"Key (hex): {key.hex()}\n"
#         f"IV (hex): {iv.hex()}"
#     )
#     label_encrypt_result.config(text=result)

# def decrypt_action(entry_ciphertext, entry_tag, entry_key, entry_iv, entry_aad, label_decrypt_result):
#     try:
#         ciphertext = bytes.fromhex(entry_ciphertext.get())
#         tag = bytes.fromhex(entry_tag.get())
#         key = bytes.fromhex(entry_key.get())
#         iv = bytes.fromhex(entry_iv.get())
#         aad = entry_aad.get()
#         t_length = 128  # Authentication tag length in bits

#         plaintext = aes_gcm_decrypt(ciphertext, tag, key, iv, aad.encode('utf-8'), t_length)
#         label_decrypt_result.config(text=f"Plaintext: {plaintext.decode('utf-8')}")
#     except ValueError as e:
#         label_decrypt_result.config(text=f"Error: {str(e)}")

# def main():
#     root = tk.Tk()
#     root.title("AES-GCM Encryption/Decryption")

#     # Encryption Section
#     frame_encrypt = tk.LabelFrame(root, text="Encryption", padx=10, pady=10)
#     frame_encrypt.pack(padx=10, pady=10, fill="x")

#     tk.Label(frame_encrypt, text="Plaintext:").grid(row=0, column=0, sticky="w")
#     entry_plaintext = tk.Entry(frame_encrypt, width=50)
#     entry_plaintext.grid(row=0, column=1, padx=5, pady=5)

#     tk.Label(frame_encrypt, text="AAD:").grid(row=1, column=0, sticky="w")
#     entry_aad = tk.Entry(frame_encrypt, width=50)
#     entry_aad.grid(row=1, column=1, padx=5, pady=5)

#     label_encrypt_result = tk.Label(frame_encrypt, text="", anchor="w", justify="left")
#     label_encrypt_result.grid(row=3, column=0, columnspan=2, sticky="w")

#     btn_encrypt = tk.Button(frame_encrypt, text="Encrypt", width=20, command=lambda: encrypt_action(entry_plaintext, entry_aad, label_encrypt_result))
#     btn_encrypt.grid(row=2, column=1, sticky="e", pady=5)

#     # Decryption Section
#     frame_decrypt = tk.LabelFrame(root, text="Decryption", padx=10, pady=10)
#     frame_decrypt.pack(padx=10, pady=10, fill="x")

#     tk.Label(frame_decrypt, text="Ciphertext (hex):").grid(row=0, column=0, sticky="w")
#     entry_ciphertext = tk.Entry(frame_decrypt, width=50)
#     entry_ciphertext.grid(row=0, column=1, padx=5, pady=5)

#     tk.Label(frame_decrypt, text="Tag (hex):").grid(row=1, column=0, sticky="w")
#     entry_tag = tk.Entry(frame_decrypt, width=50)
#     entry_tag.grid(row=1, column=1, padx=5, pady=5)

#     tk.Label(frame_decrypt, text="Key (hex):").grid(row=2, column=0, sticky="w")
#     entry_key = tk.Entry(frame_decrypt, width=50)
#     entry_key.grid(row=2, column=1, padx=5, pady=5)

#     tk.Label(frame_decrypt, text="IV (hex):").grid(row=3, column=0, sticky="w")
#     entry_iv = tk.Entry(frame_decrypt, width=50)
#     entry_iv.grid(row=3, column=1, padx=5, pady=5)

#     tk.Label(frame_decrypt, text="AAD:").grid(row=4, column=0, sticky="w")
#     entry_aad_decrypt = tk.Entry(frame_decrypt, width=50)
#     entry_aad_decrypt.grid(row=4, column=1, padx=5, pady=5)

#     label_decrypt_result = tk.Label(frame_decrypt, text="", anchor="w", justify="left")
#     label_decrypt_result.grid(row=6, column=0, columnspan=2, sticky="w")

#     btn_decrypt = tk.Button(frame_decrypt, text="Decrypt", width=20, command=lambda: decrypt_action(entry_ciphertext, entry_tag, entry_key, entry_iv, entry_aad_decrypt, label_decrypt_result))
#     btn_decrypt.grid(row=5, column=1, sticky="e", pady=5)

#     # Exit Button
#     btn_exit = tk.Button(root, text="Exit", command=root.quit, width=20)
#     btn_exit.pack(pady=10)

#     root.mainloop()

# if __name__ == "__main__":
#     main()

# def aes_gcm_encrypt(plaintext, key, iv, aad, t_length):
#     return b"ciphertext", b"tag"

# def aes_gcm_decrypt(ciphertext, tag, key, iv, aad, t_length):
#     return b"plaintext"

# def encrypt_action(entry_plaintext, entry_aad, text_encrypt_result):
#     plaintext = entry_plaintext.get()
#     aad = entry_aad.get()

#     key = os.urandom(16)  # Generate a 128-bit random key
#     iv = os.urandom(12)   # Generate a 96-bit random IV
#     t_length = 128  # Authentication tag length in bits

#     ciphertext, tag = aes_gcm_encrypt(plaintext.encode('utf-8'), key, iv, aad.encode('utf-8'), t_length)

#     result = (
#         f"Ciphertext (hex): {ciphertext.hex()}\n"
#         f"Authentication Tag (hex): {tag.hex()}\n"
#         f"Key (hex): {key.hex()}\n"
#         f"IV (hex): {iv.hex()}"
#     )
    
#     # Cập nhật kết quả trong widget Text
#     text_encrypt_result.delete(1.0, tk.END)  # Xóa nội dung cũ
#     text_encrypt_result.insert(tk.END, result)  # Hiển thị kết quả

# def decrypt_action(entry_ciphertext, entry_tag, entry_key, entry_iv, entry_aad, label_decrypt_result):
#     try:
#         ciphertext = bytes.fromhex(entry_ciphertext.get())
#         tag = bytes.fromhex(entry_tag.get())
#         key = bytes.fromhex(entry_key.get())
#         iv = bytes.fromhex(entry_iv.get())
#         aad = entry_aad.get()
#         t_length = 128  # Authentication tag length in bits

#         plaintext = aes_gcm_decrypt(ciphertext, tag, key, iv, aad.encode('utf-8'), t_length)
#         label_decrypt_result.config(text=f"Plaintext: {plaintext.decode('utf-8')}")
#     except ValueError as e:
#         label_decrypt_result.config(text=f"Error: {str(e)}")

# def main():
#     root = tk.Tk()
#     root.title("AES-GCM Encryption/Decryption")

#     # Encryption Section
#     frame_encrypt = tk.LabelFrame(root, text="Encryption", padx=10, pady=10)
#     frame_encrypt.pack(padx=10, pady=10, fill="x")

#     tk.Label(frame_encrypt, text="Plaintext:").grid(row=0, column=0, sticky="w")
#     entry_plaintext = tk.Entry(frame_encrypt, width=50)
#     entry_plaintext.grid(row=0, column=1, padx=5, pady=5)

#     tk.Label(frame_encrypt, text="AAD:").grid(row=1, column=0, sticky="w")
#     entry_aad = tk.Entry(frame_encrypt, width=50)
#     entry_aad.grid(row=1, column=1, padx=5, pady=5)

#     # Thay đổi Label thành Text widget để hiển thị kết quả và cho phép sao chép
#     text_encrypt_result = tk.Text(frame_encrypt, height=10, width=50)
#     text_encrypt_result.grid(row=3, column=0, columnspan=2, sticky="w")

#     btn_encrypt = tk.Button(frame_encrypt, text="Encrypt", width=20, command=lambda: encrypt_action(entry_plaintext, entry_aad, text_encrypt_result))
#     btn_encrypt.grid(row=2, column=1, sticky="e", pady=5)

#     # Decryption Section
#     frame_decrypt = tk.LabelFrame(root, text="Decryption", padx=10, pady=10)
#     frame_decrypt.pack(padx=10, pady=10, fill="x")

#     tk.Label(frame_decrypt, text="Ciphertext (hex):").grid(row=0, column=0, sticky="w")
#     entry_ciphertext = tk.Entry(frame_decrypt, width=50)
#     entry_ciphertext.grid(row=0, column=1, padx=5, pady=5)

#     tk.Label(frame_decrypt, text="Tag (hex):").grid(row=1, column=0, sticky="w")
#     entry_tag = tk.Entry(frame_decrypt, width=50)
#     entry_tag.grid(row=1, column=1, padx=5, pady=5)

#     tk.Label(frame_decrypt, text="Key (hex):").grid(row=2, column=0, sticky="w")
#     entry_key = tk.Entry(frame_decrypt, width=50)
#     entry_key.grid(row=2, column=1, padx=5, pady=5)

#     tk.Label(frame_decrypt, text="IV (hex):").grid(row=3, column=0, sticky="w")
#     entry_iv = tk.Entry(frame_decrypt, width=50)
#     entry_iv.grid(row=3, column=1, padx=5, pady=5)

#     tk.Label(frame_decrypt, text="AAD:").grid(row=4, column=0, sticky="w")
#     entry_aad_decrypt = tk.Entry(frame_decrypt, width=50)
#     entry_aad_decrypt.grid(row=4, column=1, padx=5, pady=5)

#     label_decrypt_result = tk.Label(frame_decrypt, text="", anchor="w", justify="left")
#     label_decrypt_result.grid(row=6, column=0, columnspan=2, sticky="w")

#     btn_decrypt = tk.Button(frame_decrypt, text="Decrypt", width=20, command=lambda: decrypt_action(entry_ciphertext, entry_tag, entry_key, entry_iv, entry_aad_decrypt, label_decrypt_result))
#     btn_decrypt.grid(row=5, column=1, sticky="e", pady=5)

#     # Exit Button
#     btn_exit = tk.Button(root, text="Exit", command=root.quit, width=20)
#     btn_exit.pack(pady=10)

#     root.mainloop()

# if __name__ == "__main__":
#     main()
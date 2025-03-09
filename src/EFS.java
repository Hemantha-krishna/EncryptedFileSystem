/**
 * @author Hemantha Krishna Challa
 * @netid HXC230046
 * @email hxc230046@utdallas.edu
 */

import java.nio.ByteBuffer;       
import java.nio.file.Path;        
import java.nio.file.Paths;       
import java.nio.file.Files;       
import java.nio.charset.StandardCharsets; 
import java.util.Arrays;          
import java.io.ByteArrayOutputStream; 
import java.io.IOException;       

public class EFS extends Utility {
    // Constants
    private static final int BLOCK_SIZE = 1024;
    private static final int SALT_SIZE = 16;
    private static final int FEK_SIZE = 16;
    private static final int MK_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int MAC_SIZE = 32;
    private static final int USERNAME_MAX = 128;
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final int DATA_PER_BLOCK = BLOCK_SIZE - MAC_SIZE;

    public EFS(Editor e) {
        super(e);
        set_username_password();
    }

    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        Path directory = Paths.get(file_name);
        Files.createDirectories(directory);
        Path meta_path = directory.resolve("0");
        if (Files.exists(meta_path)) {
            throw new Exception("File already exists");
        }

        
        byte[] salt = secureRandomNumber(SALT_SIZE);
        byte[] nonce = secureRandomNumber(NONCE_SIZE);
        byte[] fek = secureRandomNumber(FEK_SIZE);
        byte[] mk = secureRandomNumber(MK_SIZE);

        // // Derive Key Encryption Key (KEK) using PBKDF2
        byte[] kek = pbkdf2(password.toCharArray(), salt, PBKDF2_ITERATIONS, 16);

        // Encrypt FEK + MK using AES-ECB
        byte[] encryptedKeys = encrypt_AES(concat(fek, mk), kek);

        // Encrypt initial file length (0)
        byte[] encryptedLength = encrypt_AES(intToBytes(0), fek);

        // Build metadata
        ByteArrayOutputStream metadata = new ByteArrayOutputStream();
        metadata.write(padUsername(user_name));
        metadata.write(salt);
        metadata.write(encryptedKeys);
        metadata.write(nonce);
        metadata.write(encryptedLength); // Encrypted file length

        // Compute HMAC-SHA256
        byte[] mac = computeHmac(metadata.toByteArray(), mk);
        metadata.write(mac);

        // Pad metadata to BLOCK_SIZE and write to file
        byte[] paddedMetadata = Arrays.copyOf(metadata.toByteArray(), BLOCK_SIZE);
        Files.write(meta_path, paddedMetadata);
    }

    @Override
    public String findUser(String file_name) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(file_name, "0"));
        return new String(data, 0, USERNAME_MAX, StandardCharsets.UTF_8).trim();
    }

    @Override
    public int length(String file_name, String password) throws Exception {
        Metadata meta = validatePwd(file_name, password);
        return meta.file_length;
    }

    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
        Metadata meta = validatePwd(file_name, password);
        
        // Read boundaries
        if (starting_position < 0 || starting_position >= meta.file_length || len < 0 || starting_position + len > meta.file_length) {
            throw new Exception("Invalid read position/length");
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream();
        int remaining = len;
        int pos = starting_position;

        while (remaining > 0) {
            int block_num = 1 + (pos / DATA_PER_BLOCK);
            int block_offset = pos % DATA_PER_BLOCK;
            int read_len = Math.min(remaining, DATA_PER_BLOCK - block_offset);

            Path block_path = Paths.get(file_name, Integer.toString(block_num));
            byte[] block_data = Files.readAllBytes(block_path);
            verifyMac(block_data, block_num, meta.mk);

            // Decrypt and extract needed data
            byte[] ciphertext = Arrays.copyOfRange(block_data, MAC_SIZE, BLOCK_SIZE);
            byte[] plaintext = decryptCTR(ciphertext, block_num, meta.fek, meta.nonce);

            result.write(plaintext, block_offset, read_len);
            pos += read_len;
            remaining -= read_len;
        }
        return result.toByteArray();
    }

    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
        Metadata meta = validatePwd(file_name, password);
        int new_length = Math.max(meta.file_length, starting_position + content.length);
        int pos = starting_position;
        int content_offset = 0;
        int remaining = content.length;

        while (remaining > 0) {
            int block_num = 1 + (pos / DATA_PER_BLOCK);
            int block_offset = pos % DATA_PER_BLOCK;
            int write_len = Math.min(remaining, DATA_PER_BLOCK - block_offset);

            byte[] existing_data = new byte[DATA_PER_BLOCK];
            Path block_path = Paths.get(file_name, Integer.toString(block_num));
            if (Files.exists(block_path)) {
                byte[] block_data = Files.readAllBytes(block_path);
                verifyMac(block_data, block_num, meta.mk);
                byte[] ciphertext = Arrays.copyOfRange(block_data, MAC_SIZE, BLOCK_SIZE);
                existing_data = decryptCTR(ciphertext, block_num, meta.fek, meta.nonce);
            }

             // Merge new content and encrypt
            System.arraycopy(content, content_offset, existing_data, block_offset, write_len);
            byte[] ciphertext = encryptCTR(existing_data, block_num, meta.fek, meta.nonce);
            byte[] mac = computeHmac(concat(intToBytes(block_num), ciphertext), meta.mk);

            // Write updated block
            ByteArrayOutputStream block_data = new ByteArrayOutputStream();
            block_data.write(mac);
            block_data.write(ciphertext);
            Files.write(block_path, block_data.toByteArray());

            pos += write_len;
            content_offset += write_len;
            remaining -= write_len;
        }

        // Updateing metadata if file expanded
        if (new_length > meta.file_length) {
            updateMetadata(file_name, password, new_length, meta);
        }
    }

    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
        try {
            Metadata meta = validatePwd(file_name, password);
            int blocks_needed = (meta.file_length + DATA_PER_BLOCK - 1) / DATA_PER_BLOCK;
            for (int i = 1; i <= blocks_needed; i++) {
                Path block_path = Paths.get(file_name, Integer.toString(i));
                byte[] block_data = Files.readAllBytes(block_path);
                verifyMac(block_data, i, meta.mk);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public void cut(String file_name, int length, String password) throws Exception {
        Metadata meta = validatePwd(file_name, password);
        
        if (length < 0) throw new Exception("Invalid length");

        int new_blocks = (length + DATA_PER_BLOCK - 1) / DATA_PER_BLOCK;
        int old_blocks = (meta.file_length + DATA_PER_BLOCK - 1) / DATA_PER_BLOCK;

        // Delete excess blocks
        for (int i = new_blocks + 1; i <= old_blocks; i++) {
            Files.delete(Paths.get(file_name, Integer.toString(i)));
        }

        // Truncate last block if needed
        if (new_blocks > 0 && length % DATA_PER_BLOCK != 0) {
            Path block_path = Paths.get(file_name, Integer.toString(new_blocks));
            byte[] block_data = Files.readAllBytes(block_path);
            verifyMac(block_data, new_blocks, meta.mk);

            // Decrypt and truncate
            byte[] ciphertext = Arrays.copyOfRange(block_data, MAC_SIZE, BLOCK_SIZE);
            byte[] plaintext = decryptCTR(ciphertext, new_blocks, meta.fek, meta.nonce);
            byte[] truncated = Arrays.copyOf(plaintext, length % DATA_PER_BLOCK);

            // Re-encrypt and write back
            byte[] padded = Arrays.copyOf(truncated, DATA_PER_BLOCK);
            byte[] new_ciphertext = encryptCTR(padded, new_blocks, meta.fek, meta.nonce);
            byte[] new_mac = computeHmac(concat(intToBytes(new_blocks), new_ciphertext), meta.mk);

            ByteArrayOutputStream new_block = new ByteArrayOutputStream();
            new_block.write(new_mac);
            new_block.write(new_ciphertext);
            Files.write(block_path, new_block.toByteArray());
        }

        updateMetadata(file_name, password, length, meta);
    }

    
    private static class Metadata {
        byte[] fek; // File Encryption Key
        byte[] mk;  // MAC Key
        byte[] nonce;
        int file_length;
    }

    /*private Metadata validatePwd(String file_name, String password) throws Exception {
        byte[] metadata = Files.readAllBytes(Paths.get(file_name, "0"));
        if (metadata.length != BLOCK_SIZE) throw new Exception("Invalid metadata");

        

        // Parse components
        byte[] username = Arrays.copyOfRange(metadata, 0, USERNAME_MAX);
        byte[] salt = Arrays.copyOfRange(metadata, USERNAME_MAX, USERNAME_MAX + SALT_SIZE);
        byte[] encryptedKeys = Arrays.copyOfRange(metadata, USERNAME_MAX + SALT_SIZE, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE);
        byte[] nonce = Arrays.copyOfRange(metadata, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE);
        int file_length = ByteBuffer.wrap(Arrays.copyOfRange(metadata, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE + 4)).getInt();
        byte[] storedMac = Arrays.copyOfRange(metadata, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE + 4, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE + 4 + MAC_SIZE);

        // Derive KEK
        byte[] kek = pbkdf2(password.toCharArray(), salt, PBKDF2_ITERATIONS, 16);

        // Decrypt FEK + MK
        byte[] keys = decrypt_AES(encryptedKeys, kek);
        byte[] fek = Arrays.copyOfRange(keys, 0, FEK_SIZE);
        byte[] mk = Arrays.copyOfRange(keys, FEK_SIZE, FEK_SIZE + MK_SIZE);

        // Verify HMAC
        ByteArrayOutputStream metadataData = new ByteArrayOutputStream();
        metadataData.write(username);
        metadataData.write(salt);
        metadataData.write(encryptedKeys);
        metadataData.write(nonce);
        metadataData.write(intToBytes(file_length));
        byte[] computedMac = computeHmac(metadataData.toByteArray(), mk);

        if (!Arrays.equals(computedMac, storedMac)) {
            throw new PasswordIncorrectException();
        }

        Metadata meta = new Metadata();
        meta.fek = fek;
        meta.mk = mk;
        meta.nonce = nonce;
        meta.file_length = file_length;
        return meta;
    }
     */

     private Metadata validatePwd(String file_name, String password) throws Exception {
        // Read entire metadata block (1024 bytes)
        byte[] metadata = Files.readAllBytes(Paths.get(file_name, "0"));
        if (metadata.length != BLOCK_SIZE) {
            throw new Exception("Invalid metadata block size");
        }
    
        // Parse components with new encrypted length structure
        final int BASE_OFFSET = USERNAME_MAX + SALT_SIZE;
        byte[] username = Arrays.copyOfRange(metadata, 0, USERNAME_MAX);
        byte[] salt = Arrays.copyOfRange(metadata, USERNAME_MAX, USERNAME_MAX + SALT_SIZE);
        byte[] encryptedKeys = Arrays.copyOfRange(metadata, BASE_OFFSET, BASE_OFFSET + FEK_SIZE + MK_SIZE);
        byte[] nonce = Arrays.copyOfRange(metadata, BASE_OFFSET + FEK_SIZE + MK_SIZE, 
                                          BASE_OFFSET + FEK_SIZE + MK_SIZE + NONCE_SIZE);
        byte[] encryptedLength = Arrays.copyOfRange(metadata, 
                                          BASE_OFFSET + FEK_SIZE + MK_SIZE + NONCE_SIZE,
                                          BASE_OFFSET + FEK_SIZE + MK_SIZE + NONCE_SIZE + 16);
        byte[] storedMac = Arrays.copyOfRange(metadata, 
                                          BASE_OFFSET + FEK_SIZE + MK_SIZE + NONCE_SIZE + 16,
                                          BASE_OFFSET + FEK_SIZE + MK_SIZE + NONCE_SIZE + 16 + MAC_SIZE);
    
        // Derive KEK using PBKDF2
        byte[] kek = pbkdf2(password.toCharArray(), salt, PBKDF2_ITERATIONS, 16);
    
        // Decrypt FEK and MK
        byte[] keys = decrypt_AES(encryptedKeys, kek);
        if (keys.length != FEK_SIZE + MK_SIZE) {
            throw new PasswordIncorrectException();
        }
        byte[] fek = Arrays.copyOfRange(keys, 0, FEK_SIZE);
        byte[] mk = Arrays.copyOfRange(keys, FEK_SIZE, FEK_SIZE + MK_SIZE);
    
        // Decrypt file length
        byte[] decryptedLength = decrypt_AES(encryptedLength, fek);
        int file_length = ByteBuffer.wrap(decryptedLength).getInt();
    
        // Verify HMAC
        ByteArrayOutputStream hmacData = new ByteArrayOutputStream();
        hmacData.write(username);
        hmacData.write(salt);
        hmacData.write(encryptedKeys);
        hmacData.write(nonce);
        hmacData.write(encryptedLength);
        
        byte[] computedMac = computeHmac(hmacData.toByteArray(), mk);
        
        if (!constantTimeCompare(storedMac, computedMac)) {
            throw new PasswordIncorrectException();
        }
    
        // Return validated metadata
        Metadata meta = new Metadata();
        meta.fek = fek;
        meta.mk = mk;
        meta.nonce = nonce;
        meta.file_length = file_length;
        return meta;
    }
    


    // Updates file metadata with new length and recomputes HMAC
    /*private void updateMetadata(String file_name, String password, int new_length, Metadata meta) throws Exception {
        byte[] metadata = Files.readAllBytes(Paths.get(file_name, "0"));
        System.arraycopy(intToBytes(new_length), 0, metadata, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE, 4);

        // Recompute HMAC
        ByteArrayOutputStream metadataData = new ByteArrayOutputStream();
        metadataData.write(metadata, 0, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE + 4);
        byte[] newMac = computeHmac(metadataData.toByteArray(), meta.mk);
        System.arraycopy(newMac, 0, metadata, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE + 4, MAC_SIZE);

        Files.write(Paths.get(file_name, "0"), metadata);
    }*/
    private void updateMetadata(String file_name, String password, int new_length, Metadata meta) throws Exception {
        // Encrypt new length
        byte[] encryptedLength = encrypt_AES(intToBytes(new_length), meta.fek);
    
        // Read existing metadata
        byte[] metadata = Files.readAllBytes(Paths.get(file_name, "0"));
        
        // Update encrypted length
        System.arraycopy(
            encryptedLength, 0,
            metadata, 
            USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE,
            encryptedLength.length
        );
    
        // Recompute HMAC
        ByteArrayOutputStream metadataData = new ByteArrayOutputStream();
        metadataData.write(metadata, 0, USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE + 16);
        byte[] newMac = computeHmac(metadataData.toByteArray(), meta.mk);
        
        // Update HMAC in metadata
        System.arraycopy(
            newMac, 0,
            metadata, 
            USERNAME_MAX + SALT_SIZE + FEK_SIZE + MK_SIZE + NONCE_SIZE + 16,
            MAC_SIZE
        );
    
        Files.write(Paths.get(file_name, "0"), metadata);
    }

    //Custom PBKDF2 implementation
    private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLength) throws Exception {
        byte[] key = new byte[keyLength];
        int blocks = (keyLength + 31) / 32; // SHA-256 produces 32-byte hashes

        for (int i = 1; i <= blocks; i++) {
            byte[] block = hmacSha256(password, concat(salt, intToBytes(i)));
            byte[] prev = block.clone();
            for (int j = 1; j < iterations; j++) {
                prev = hmacSha256(password, prev);
                xor(block, prev);
                
            }
            System.arraycopy(block, 0, key, (i - 1) * 32, Math.min(32, key.length - (i - 1) * 32));
        }
        return key;
    }

    private byte[] hmacSha256(char[] password, byte[] data) throws Exception {
        byte[] keyBytes = new String(password).getBytes(StandardCharsets.UTF_8);
        return computeHmac(data, keyBytes);
    }

    //Computes hmac using SHA-256
    private byte[] computeHmac(byte[] data, byte[] key) throws Exception {
        int blockSize = 64; // SHA-256 block size
        byte[] paddedKey = key.length > blockSize ? hash_SHA256(key) : Arrays.copyOf(key, blockSize);
        byte[] oKeyPad = new byte[blockSize];
        byte[] iKeyPad = new byte[blockSize];
        for (int i = 0; i < blockSize; i++) {
            oKeyPad[i] = (byte) (0x5C ^ paddedKey[i]);
            iKeyPad[i] = (byte) (0x36 ^ paddedKey[i]);
        }
        byte[] innerHash = hash_SHA256(concat(iKeyPad, data));
        return hash_SHA256(concat(oKeyPad, innerHash));
    }

    //CTR mode encryption using AES
    /*private byte[] encryptCTR(byte[] plaintext, int block_num, byte[] fek, byte[] nonce) throws Exception {
    ByteBuffer ivBuffer = ByteBuffer.allocate(16);
    ivBuffer.put(nonce);
    ivBuffer.putInt(block_num);
    byte[] counter = ivBuffer.array();

    byte[] keystream = encrypt_AES(counter, fek);
    byte[] ciphertext = new byte[plaintext.length];
    for (int i = 0; i < plaintext.length; i++) {
        ciphertext[i] = (byte) (plaintext[i] ^ keystream[i % 16]);
    }
    return ciphertext;
}*/
private byte[] encryptCTR(byte[] plaintext, int block_num, byte[] fek, byte[] nonce) throws Exception {
    ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();
    int numChunks = (plaintext.length + 15) / 16; // Number of 16-byte chunks
    for (int i = 0; i < numChunks; i++) {
        // Create counter: nonce (12) + block_num (4) + chunk index (4)
        ByteBuffer counterBuf = ByteBuffer.allocate(16);
        counterBuf.put(nonce);
        counterBuf.putInt(block_num);
        counterBuf.putInt(i); // Increment for each chunk
        byte[] counter = counterBuf.array();
        
        byte[] keystream = encrypt_AES(counter, fek);
        int chunkLength = Math.min(16, plaintext.length - i * 16);
        byte[] chunk = Arrays.copyOfRange(plaintext, i * 16, i * 16 + chunkLength);
        byte[] encryptedChunk = xorBytes(chunk, keystream);
        ciphertextStream.write(encryptedChunk);
    }
    return ciphertextStream.toByteArray();
}

    // decryptCTR uses identical logic to encryptCTR (CTR is symmetric)
    private byte[] decryptCTR(byte[] ciphertext, int block_num, byte[] fek, byte[] nonce) throws Exception {
        return encryptCTR(ciphertext, block_num, fek, nonce); 
    }
    
    private byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i % b.length]);
        }
        return result;
    }
   
    private byte[] padUsername(String username) {
        return Arrays.copyOf(username.getBytes(StandardCharsets.UTF_8), USERNAME_MAX);
    }

    private byte[] concat(byte[] a, byte[] b) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            output.write(a);
            output.write(b);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return output.toByteArray();
    }

    private byte[] intToBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    private void xor(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            a[i] ^= b[i % b.length];
        }
    }

    /*private void verifyMac(byte[] blockData, int blockNum, byte[] mk) throws Exception {
    if (blockData.length != BLOCK_SIZE) {
        throw new Exception("Invalid block size");
    }
    
    byte[] storedMac = Arrays.copyOfRange(blockData, 0, MAC_SIZE);
    byte[] ciphertext = Arrays.copyOfRange(blockData, MAC_SIZE, BLOCK_SIZE);
    byte[] computedMac = computeHmac(concat(intToBytes(blockNum), ciphertext), mk);
    if (!constantTimeCompare(storedMac, computedMac)) {
        throw new Exception("MAC verification failed");
    }
    
}*/
private void verifyMac(byte[] blockData, int blockNum, byte[] mk) throws Exception {
    if (blockData.length != BLOCK_SIZE) {
        throw new Exception("Invalid block size");
    }
    
    byte[] storedMac = Arrays.copyOfRange(blockData, 0, MAC_SIZE);
    byte[] ciphertext = Arrays.copyOfRange(blockData, MAC_SIZE, BLOCK_SIZE);
    
    // Include block number in MAC computation
    ByteArrayOutputStream macData = new ByteArrayOutputStream();
    macData.write(intToBytes(blockNum));
    macData.write(ciphertext);
    
    byte[] computedMac = computeHmac(macData.toByteArray(), mk);
    
    if (!constantTimeCompare(storedMac, computedMac)) {
        throw new Exception("MAC verification failed");
    }
}
//Constant-time HMAC comparison
private boolean constantTimeCompare(byte[] a, byte[] b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (int i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}
}
/**
 * @author Hemantha Krishna Challa
 * @netid hxc230046
 * @email hxc230046@utdallas.edu
 */

import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.io.*;

public class EFS extends Utility{

    private static final int BLOCK_SIZE = 1024;
    private static final int SALT_SIZE = 16;
    private static final int FEK_SIZE = 16; //FEk = File Encryption Key
    private static final int MK_SIZE = 16; //MK = Metadata Key
    private static final int NONCE_SIZE = 8;
    private static final int MAC_SIZE = 32; // HMAC-SHA256
    private static final int USERNAME_MAX = 128;
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final int DATA_PER_BLOCK = BLOCK_SIZE - MAC_SIZE;
    

    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

   
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
        
        Path directory = Paths.get(file_name);
        Files.createDirectories(directory);
        
        Path meta_path=directory.resolve("0");
        if(Files.exists(meta_path))
        {
            throw new Exception("File already exists");
        }

        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);

        byte[] mk = new byte[MK_SIZE];
        random.nextBytes(mk);

        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(nonce);

        byte[] fek = new byte[FEK_SIZE];
        random.nextBytes(fek);

        //Getting Key Encryption Key(KEK) from password. KEK is the master Key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2_With_HmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 128);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKeySpec kek = new SecretKeySpec(tmp.getEncoded(), "AES");

        //Encrypting the File Encryption Key(FEK) and Metadata Key(MK) using KEK
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, kek);
        byte[] encryptedKeys = cipher.doFinal(ByteBuffer.allocate(FEK_SIZE + MK_SIZE).put(fek).put(mk).array());

        //Metadata 
        ByteArrayOutputStream metadata = new ByteArrayOutputStream();
        metadata.write(Arrays.copyOf(user_name.getBytes(StandardCharsets.UTF_8), USERNAME_MAX));

    }

    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
    	return null;
    }



























    
    /**
     * Steps to consider...:<p>
     *  - get password, salt then AES key <p>     
     *  - decrypt password hash out of encrypted secret data <p>
     *  - check the equality of the two password hash values <p>
     *  - decrypt file length out of encrypted secret data
     */
    @Override
    public int length(String file_name, String password) throws Exception {
    	return 0;
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
    	return null;
    }

    

















    
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
    }

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
    	return true;
  }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
    }
  
}

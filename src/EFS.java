/**
 * @author Hemantha Krishna Challa
 * @netid hxc230046
 * @email hxc230046@utdallas.edu
 */


import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;


public class EFS extends Utility{

    private static final int BLOCK_SIZE = 1024;
    private static final int SALT_SIZE = 16;
    private static final int FEK_SIZE = 16; //FEk = File Encryption Key
    private static final int MK_SIZE = 16; //MK = Metadata Key
    private static final int NONCE_SIZE = 12;
    private static final int MAC_SIZE = 32; // HMAC-SHA256
    private static final int USERNAME_MAX = 128;
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final int DATA_PER_BLOCK = BLOCK_SIZE - MAC_SIZE;
    

    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

    private static class Metadata{
        byte[] fek;
        byte[] mk;
        byte[] nonce;
        int file_length;
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

        
        byte[] salt = secureRandomNumber(SALT_SIZE);
        byte[] kekBytes=pbkdf2Derive(password,salt);


        // Generate random keys
        byte[] fek = secureRandomNumber(FEK_SIZE);
        byte[] mk = secureRandomNumber(MK_SIZE);
        byte[] nonce = secureRandomNumber(NONCE_SIZE);

       // Encrypt FEK and MK with KEK using ECB
        byte[] encryptedFek = encrypt_AES(fek, kekBytes);
        byte[] encryptedMk = encrypt_AES(mk, kekBytes);

        //Metadata 
        //ByteBuffer metabuff = ByteBuffer.allocate(BLOCK_SIZE).put(pad(user_name, USERNAME_MAX)).put(salt).put(encryptedFek).put(encryptedMk).put(nonce).putInt(0);
ByteArrayOutputStream metadata = new ByteArrayOutputStream();
        metadata.write(Arrays.copyOf(user_name.getBytes(StandardCharsets.UTF_8), USERNAME_MAX));
        metadata.write(salt);
        metadata.write(encryptedFek);
        metadata.write(encryptedMk);
        metadata.write(nonce);
        metadata.write(ByteBuffer.allocate(4).putInt(0).array());

        //HMAC metadat
        byte[] mac = computeHmac(metadata.toByteArray(), mk);
        metadata.write(mac);

        //Writing metadata to file
        Files.write(meta_path, Arrays.copyOf(metadata.toByteArray(), BLOCK_SIZE));
    }

    /**
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
    	byte[] data=Files.readAllBytes(Paths.get(file_name,"0"));
        return new String(data, 0, USERNAME_MAX, StandardCharsets.UTF_8).trim();
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
    	Metadata meta = validate_pwd(file_name, password);
        return meta.file_length;
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
    	Metadata meta=validate_pwd(file_name,password);

        if(starting_position<0 || starting_position>=meta.file_length || len<0 || starting_position+len>meta.file_length)
        {
            throw new IllegalArgumentException("Invalid starting position or length");
        }

        len=Math.min(len,meta.file_length-starting_position);
        ByteArrayOutputStream result=new ByteArrayOutputStream();

        int rem=len;
        int pos=starting_position; //current position

        while(rem>0){
            int block_num=1+pos/DATA_PER_BLOCK; //Block number
            int block_offset=pos%DATA_PER_BLOCK; //Position within block
            int read_len=Math.min(rem,DATA_PER_BLOCK-block_offset); //Length to read

            Path block_path=Paths.get(file_name,Integer.toString(block_num));
            if(!Files.exists(block_path))
            {
                throw new Exception("Block not found");
            }

            byte[] block_data=Files.readAllBytes(block_path);
            verify_mac(block_data,block_num,meta.mk);

            //Decryption
            byte[] plaintext = decryptCTR(Arrays.copyOfRange(block_data,MAC_SIZE,BLOCK_SIZE),block_num,meta.fek,meta.nonce);

            result.write(plaintext,block_offset,read_len);
            pos+=read_len;
            rem-=read_len;
        }
        return result.toByteArray();
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
    
        Metadata meta=validate_pwd(file_name,password);
        int len2=Math.max(meta.file_length,starting_position+content.length);

        int rem=content.length;
        int pos=starting_position;
        int content_offset=0;

        while(rem>0){
            int block_num=1+pos/DATA_PER_BLOCK;
            int block_offset=pos%DATA_PER_BLOCK;
            int write_len=Math.min(rem,DATA_PER_BLOCK-block_offset);

            byte[] existing_data=new byte[DATA_PER_BLOCK];
            if(block_num<=(meta.file_length+DATA_PER_BLOCK-1)/DATA_PER_BLOCK)
            {
                Path block_path=Paths.get(file_name,Integer.toString(block_num));
                if(Files.exists(block_path))
                {
                    byte[] block_data=Files.readAllBytes(block_path);
                    verify_mac(block_data,block_num,meta.mk);
                    existing_data=decryptCTR(Arrays.copyOfRange(block_data,MAC_SIZE,BLOCK_SIZE),block_num,meta.fek,meta.nonce);
                }
            }
            System.arraycopy(content, content_offset, existing_data, block_offset, write_len);
            byte[] new_block=encryptCTR(existing_data,block_num,meta.fek,meta.nonce);
            byte[] mac=compute_mac(new_block,block_num,meta.mk);

            ByteArrayOutputStream block_data=new ByteArrayOutputStream();
            block_data.write(mac);
            block_data.write(new_block);
            Files.write(Paths.get(file_name,Integer.toString(block_num)),block_data.toByteArray());

            pos+=write_len;
            content_offset+=write_len;
            rem-=write_len;
        }

        if(len2>meta.file_length)
        {
            update_metadata(file_name,password,len2,meta);
        }
    }
    

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
    	try{
            Metadata meta=validate_pwd(file_name,password);
            int blocks_needed=(meta.file_length+DATA_PER_BLOCK-1)/DATA_PER_BLOCK;
            for(int i=1;i<=blocks_needed;i++)
            {
                Path block_path=Paths.get(file_name,Integer.toString(i));
                if(!Files.exists(block_path))
                {
                    return false;
                }
                byte[] block_data=Files.readAllBytes(block_path);
                verify_mac(block_data,i,meta.mk);
            }
            return true;
        }
        catch(Exception e)
        {
            return false;
        }
  }

    /**
     * Steps to consider... <p>
     *  - verify password <p>
     *  - truncate the content after the specified length <p>
     *  - re-pad, update metadata and HMAC <p>
     */
    @Override
    public void cut(String file_name, int length, String password) throws Exception {
        	Metadata meta=validate_pwd(file_name,password);
            if(length<0)
            {
                throw new Exception("Invalid length");
            }
            
            int newblocks=(length+DATA_PER_BLOCK-1)/DATA_PER_BLOCK;
            int oldblocks=(meta.file_length+DATA_PER_BLOCK-1)/DATA_PER_BLOCK;

            // Remove ectra blocks
            for(int i=newblocks+1;i<=oldblocks;i++)
            {
                Files.delete(Paths.get(file_name,Integer.toString(i)));
            }

            //Remove last block if needed
            if(newblocks>0 && length%DATA_PER_BLOCK!=0)
            {
                Path block_path=Paths.get(file_name,Integer.toString(newblocks));
                byte[] block_data=Files.readAllBytes(block_path);
                verify_mac(block_data,newblocks,meta.mk);
                
                byte[] plaintext=decryptCTR(Arrays.copyOfRange(block_data,MAC_SIZE,BLOCK_SIZE),newblocks,meta.fek,meta.nonce);
                
                int newsize=length % DATA_PER_BLOCK;
                byte[] truncated_block=Arrays.copyOf(plaintext,newsize);

                byte[] padded_block = Arrays.copyOf(truncated_block, DATA_PER_BLOCK);

                byte[] encrypted_block=encryptCTR(padded_block,newblocks,meta.fek,meta.nonce);
                byte[] mac=compute_mac(encrypted_block,newblocks,meta.mk);
                

                ByteArrayOutputStream new_block_data=new ByteArrayOutputStream();
                new_block_data.write(mac);
                new_block_data.write(encrypted_block);
                Files.write(block_path,new_block_data.toByteArray());
            }

            
    
            update_metadata(file_name,password,length,meta);
    }

    

    private Metadata validate_pwd(String file_name, String password) throws Exception {
        byte[] metadata=Files.readAllBytes(Paths.get(file_name,"0"));
        if(metadata.length!=BLOCK_SIZE)
        {
            throw new Exception("Invalid metadata size");
        }

        //parse metadat components
        byte[] username=Arrays.copyOfRange(metadata,0,USERNAME_MAX);
        byte[] salt=Arrays.copyOfRange(metadata,USERNAME_MAX,USERNAME_MAX+SALT_SIZE);
        //byte[] encryptedKeys=Arrays.copyOfRange(metadata,USERNAME_MAX+SALT_SIZE,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE);
        byte[] encryptedFek = Arrays.copyOfRange(metadata, USERNAME_MAX+SALT_SIZE, USERNAME_MAX+SALT_SIZE+FEK_SIZE);
        byte[] encryptedMk = Arrays.copyOfRange(metadata, USERNAME_MAX+SALT_SIZE+FEK_SIZE, USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE);
        byte[] nonce=Arrays.copyOfRange(metadata,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE+NONCE_SIZE);

        int file_length=ByteBuffer.wrap(Arrays.copyOfRange(metadata,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE+NONCE_SIZE,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE+NONCE_SIZE+4)).getInt();
        byte[] mac_stored=Arrays.copyOfRange(metadata,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE+NONCE_SIZE+4,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE+NONCE_SIZE+4+MAC_SIZE);

        // Key derivation using YOUR password flow
        byte[] kekBytes = pbkdf2Derive(password, salt);

        byte[] fek = decrypt_AES(encryptedFek, kekBytes);
        byte[] mk = decrypt_AES(encryptedMk, kekBytes);
        
        //byte[] mk=Arrays.copyOfRange(keys,FEK_SIZE,FEK_SIZE+MK_SIZE);

        //verify metadata
        ByteArrayOutputStream metadata_data=new ByteArrayOutputStream();
        metadata_data.write(username);
        metadata_data.write(salt);
        //metadata_data.write(encryptedKeys);
        metadata_data.write(encryptedFek);
        metadata_data.write(encryptedMk);
        metadata_data.write(nonce);
        metadata_data.write(ByteBuffer.allocate(4).putInt(file_length).array());
        
        Mac hmac=Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(mk,"HmacSHA256"));

        /*if(!MessageDigest.isEqual(hmac.doFinal(metadata_data.toByteArray()),mac_stored))
        {
            throw new Exception("Metadata verification failed");
        
        }*/
        byte[] computedMac = computeHmac(metadata_data.toByteArray(), mk);
        if (!MessageDigest.isEqual(computedMac, mac_stored)) {
            throw new PasswordIncorrectException(); // Changed exception type
        }

        Metadata meta=new Metadata();
        meta.fek=fek;
        meta.mk=mk;
        meta.nonce=nonce;
        meta.file_length=file_length;
        return meta;
    }

    private void update_metadata(String file_name, String password, int newlength, Metadata meta) throws Exception {
        byte[] metadata=Files.readAllBytes(Paths.get(file_name,"0"));
       
        //updatieng length
        System.arraycopy(ByteBuffer.allocate(4).putInt(newlength).array(),0,metadata,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE+NONCE_SIZE,4);

        //recalculate mac
        byte[] metadataWithoutMac = Arrays.copyOfRange(metadata, 0, BLOCK_SIZE - MAC_SIZE);
        byte[] newmac = computeHmac(metadataWithoutMac, meta.mk);

        System.arraycopy(newmac,0,metadata,USERNAME_MAX+SALT_SIZE+FEK_SIZE+MK_SIZE+NONCE_SIZE+4,MAC_SIZE);
        Files.write(Paths.get(file_name,"0"),metadata);
    }
  
    private byte[] compute_mac(byte[] ciphertext, int block_num, byte[] mk) throws Exception {
        ByteBuffer data = ByteBuffer.allocate(ciphertext.length + 4)
                                .put(ciphertext)
                                .putInt(block_num);
    return computeHmac(data.array(), mk);
    }

    private void verify_mac(byte[] block_data, int block_num, byte[] mk) throws Exception {
        if(block_data.length!=BLOCK_SIZE)
        {
            throw new Exception("Invalid block size");
        }
        byte[] mac_stored=Arrays.copyOfRange(block_data,0,MAC_SIZE);
        byte[] ciphertext=Arrays.copyOfRange(block_data,MAC_SIZE,BLOCK_SIZE);
        byte[] mac_computed=compute_mac(ciphertext,block_num,mk);

        if(!MessageDigest.isEqual(mac_stored,mac_computed))
        {
            throw new Exception("MAC verification failed");
        }
    }

    private byte[] pbkdf2Derive(String password, byte[] salt) throws Exception {
        byte[] derivedKey = new byte[FEK_SIZE + MK_SIZE];
        byte[] block = null;
        
        for(int i=0; i<PBKDF2_ITERATIONS; i++) {
            ByteBuffer input = ByteBuffer.allocate(salt.length + 4)
                .put(salt)
                .putInt(i);
            
            byte[] hmac = computeHmac(input.array(), password.getBytes(StandardCharsets.UTF_8));
            if(block != null) {
                for(int j=0; j<hmac.length; j++) {
                    hmac[j] ^= block[j];
                }
            }
            
            int copyLen = Math.min(hmac.length, derivedKey.length);
            System.arraycopy(hmac, 0, derivedKey, 0, copyLen);
            derivedKey = Arrays.copyOfRange(derivedKey, copyLen, derivedKey.length);
            block = hmac;
        }
        return derivedKey;
    }

    private byte[] computeHmac(byte[] data, byte[] key) throws Exception {
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];
        Arrays.fill(ipad, (byte)0x36);
        Arrays.fill(opad, (byte)0x5C);
        
        for(int i=0; i<key.length; i++) {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }
        
        byte[] inner = hash_SHA256(ByteBuffer.wrap(ipad).put(data).array());
        return hash_SHA256(ByteBuffer.wrap(opad).put(inner).array());
    }

    private byte[] decryptCTR(byte[] ciphertext, int block_num, byte[] fek, byte[] nonce) throws Exception {
        ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
        
        for(int i=0; i<ciphertext.length; i+=16) {
            ByteBuffer ivBuf = ByteBuffer.allocate(16)
                .put(nonce)
                .putInt(block_num)
                .putInt(i/16);
            
            byte[] keystream = encrypt_AES(ivBuf.array(), fek);
            
            int end = Math.min(i+16, ciphertext.length);
            for(int j=i; j<end; j++) {
                plaintext.write(ciphertext[j] ^ keystream[j-i]);
            }
        }
        return plaintext.toByteArray();
    }

    private byte[] encryptCTR(byte[] plaintext, int block_num, byte[] fek, byte[] nonce) throws Exception {
        return decryptCTR(plaintext, block_num, fek, nonce); // CTR uses same logic for encrypt/decrypt
    }

    
}

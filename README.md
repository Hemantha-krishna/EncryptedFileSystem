
Project Requirements
Functionality requirements

To simulate a file system, files are stored in blocks of fixed size. More specifically, a file will be stored in a directory which has the same name as the file. The file will be split into trunks and stored into different physical files. That is, a file named /abc.txt is stored in a directory /abc.txt/, which includes one or more physical files: /abc.txt/0, /abc.text/1, and so on. Each physical file is of size exactly 1024 bytes, to simulate a disk block. You need to implement the following functions:

    void create(String file_name, String user_name, String password): Create a file that can be opened by someone who knows both user name and password. Both user name and password are ASCII strings of at most 128 bytes.

    String findUser(String file_name): Return the user name associated with a file.

    int length(String file_name, String password): Return the length of a file, provided that the given password matches the one specified in creation. If it does not match, your code should throw an exception.

    byte[] read(String file_name, int starting_position, int length, String password): Return the content of a file for a specified segment, provided that the given password matches. If it does not match, your code should throw an exception.

    void write(String file_name, int starting_position, byte[] content, String password): Write new content into a file at a specified position, provided that the given password matches. If it does not match, the file should not be changed and your code should throw an exception.

    void cut(String file_name, int length, String password): Cut a file to be the specified length, provided that the password matches. If it does not match, no change should occur and your code should throw an exception.

    boolean check_integrity(String file_name, String password): Check that a file has not been modified outside the EFS interface. If someone has modified the file content or meta-data without using the write call, return False; otherwise, return True, provided that the given password matches. If it does not match, your code should throw an exception.

Security requirements

We have the following security requirements.

    Meta-data storage: You will need to store some meta-data for each file. In a file system, this is naturally stored in the i-node data structure. In this project, we require that meta-data are stored as part of the physical files. You will need to decide where to put such data (e.g. at the beginning of the physical files), and also what cryptographic operations need to be performed to the meta-data. Naturally the first physical file would contain some meta-data, however, you can also store meta-data in other physical files.

    User authentication: You need to ensure that if the password does not match, reading and writing will not be allowed. You thus need to store something that is derived from the password; however, you should make it as difficult as possible for an adversary who attempts to recover the password from the stored information (perhaps using a dictionary attack).

    Encryption keys: In an EFS, we can choose to use one single key to encrypt all the files in the file system; or we can choose to encrypt each file using a different key. In this project, we choose the latter approach, in order to reduce the amount of data encrypted under one key.

    Encryption algorithm and modes: You are required to use AES with 128-bit block size and 128-bit key size. The code for encrypting/decrypting one block (i.e. 128 bits) is provided. When you encrypt/decrypt data that are more than one blocks, you are required to use CTR, the Counter mode. You will need to decide how to generate the IV's (initial vectors). For encryption, you can treat a file as a message, treat a chunk (stored in one physical file) as a message, or choose some other design.

    Adversarial model: We assume that an adversary may read the content of files stored on the disk from time to time. In particular, a file may be written multiple times, and the adversary may observed the content on disk between modifications. Your design and implementation should be secure against such an adversary.

    File length: You design should also hide the length of the file as much as possible. The number of physical files used for a file will leak some information about the file length; however, your design should not leak any additional information. That is, if files of length 1,700 bytes and 1,800 bytes both need 2 physical files, then an adversary should not be able to tell which is the case.

    Message authentication: We want to detect unauthorized modification to the encrypted files. In particular, if the adversaries modify the file by directly accessing the disk containing the EFS, we want to detect such modifications. Modification to other meta-data such as the user or file length should also be detected. Message Authentication Code (MAC) can help. You need to decide what specific algorithm to use, and how to combine encryption and MAC.

Efficiency requirements

We also have the following two efficiency requirements.

    Storage: We want to minimize the number of physical files used for each file.

    Speed: We want minimize the number of physical files accessed for each read or write operation. That is, if an write operation changes only one byte in the file, we want to access as small a number of physical files as possible, even if the file is very long.

These two efficiency goals may be mutually conflicting. You need to choose a design that offers a balanced tradeoff.

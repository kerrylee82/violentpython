import crypt
import bcrypt


_prefixMapHashway = {b"$2a": "BCRYPT",
                     b"$2b": "BCRYPT",
                     b"$2y": "BCRYPT",
                     b"$1": "MD5",
                     b"$5": "SHA256",
                     b"$6": "SHA512"}


def getHashedPass(rawpass, saltstr=None):
    """
    return the hashed value with crypt password, but it's not support bcrypt.
    If bcrypt use getHashedPassWithBcrypt function.
    """
    if saltstr is None:
        raise IOError

    li = saltstr.split(b'$')
    if len(li) != 4:
        raise IOError
    salt = b'$'.join(li[0:3])

    hashed = crypt.crypt(rawpass.decode("utf-8"), salt.decode("utf-8"))
    return hashed == saltstr.decode("utf-8")


def getHashedPassWithBcrypt(rawpass, saltstr=None):
    """
    return the hashed value with bcrypt pasword.
    """
    if saltstr is None:
        raise IOError

    hashed = bcrypt.hashpw(rawpass, saltstr)
    return hashed == saltstr


_encryptway = {"NOPASSWORD": lambda x, y: True,
               "BCRYPT": getHashedPassWithBcrypt,
               "MD5": getHashedPass,
               "SHA256": getHashedPass,
               "SHA512": getHashedPass,
               "UNRECOGNIZED": None}


def _getHashedWay(hashstr):
    try:
        lHashStr = hashstr.lower()
        # Check if the string is empty, if that, it means the account can
        # logged in without password!
        if len(lHashStr.strip()) == 0:
            return "NOPASSWORD"

        # check if the hashed way is bcrypt, if yes, return "BCRYPT"
        for item in _prefixMapHashway.keys():
            if lHashStr.find(item) == 0:
                return _prefixMapHashway.get(item)

        return "UNRECOGNIZED"

    except Exception as e:
        print("Unhandling exception: {e}".format(e))
        raise e


def matchTheGuessPass(word, hashstr):
    """Check whether the word is the password that match the hashstr. PS: the
    hashstr is hashed value at /etc/shadow at linux system, 2nd column.

    :word: A bytes that's a word which will be used to do hash check, whether
    it's the correct password. Such as b'Kerry.li3'
    :hashstr: the hashed bytes which means the encrpted password at
    /etc/shadow.
    :returns: A list. list[0]: True means match, then list[1] is the hash
    function str, it can be "SHA1", "SHA256", "SHA512", "BCRYPT" etc.
    if list[0]: False means unmatch, then list[1] is an empty string.

    """
    match = False
    # The input word and hashstr should be bytes type, such as b"Kerry.li3"
    hashedway = _getHashedWay(hashstr)
    hashfunc = _encryptway.get(hashedway)
    if hashfunc is not None:
        match = hashfunc(word, hashstr)

    return [match, hashedway]


def testMatchByDictionary(dictFilepath, hashedPass):
    """hashPass is a hashed value such as '$2a$10$.qVLR3WBnv/JCK8UkHLnBe/UomaZfNZMMZ.Z8RCWoqVtJIyVUDBtC'

    :dictFilepath: A path string to the dictionary file. Will open and read the
    file line by line to fetch the guessed password.
    :hashedPass: A string or a bytes of hashed password.
    :returns: [True, password] or [False, None]

    """
    isinstance(hashedPass, str)
    if isinstance(hashedPass, str):
        hashedPass = hashedPass.encode()
    elif isinstance(hashedPass, bytes):
        pass
    else:
        raise IOError

    # open the filePath to do check
    with open(dictFilepath, mode='r') as f:
        for word in f:
            word = word.strip('\n')
            if isinstance(word, str):
                word = word.encode()
            result = matchTheGuessPass(word, hashedPass)
            if result[0]:
                return [result[0], word.decode("utf-8")]

    return [False, None]


# The test for this module.
if __name__ == "__main__":
    result = matchTheGuessPass(b"haha", b"   ")
    print(result)
    result = matchTheGuessPass(b"Kerry.li3",
                               b'$2a$10$.qVLR3WBnv/JCK8UkHLnBe/UomaZfNZMMZ.Z8RCWoqVtJIyVUDBtC')
    print(result)
    result = matchTheGuessPass(b"Changeme_123",
                               b'$2a$10$.qVLR3WBnv/JCK8UkHLnBe/UomaZfNZMMZ.Z8RCWoqVtJIyVUDBtC')
    print(result)

    result = matchTheGuessPass(b"Kerry.li3",
                               b'$6$sjrB9umH$0SCIjGiD4TfpYgdWyjmLUO7kQa/E6un9vX7aSy7XiWg3WHv6rnZRFYqYoHF8QKidtvw1J80YD81rJKbZ2yCdy1')
    print(result)

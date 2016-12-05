import crypt
import bcrypt


_prefixMapHashway = {"$2a": "BCRYPT",
                     "$2b": "BCRYPT",
                     "$2y": "BCRYPT",
                     "$1": "MD5",
                     "$5": "SHA256",
                     "$6": "SHA512"}


def getHashedPass(rawpass, saltstr=None):
    """
    return the hashed value with crypt password, but it's not support bcrypt.
    If bcrypt use getHashedPassWithBcrypt function.
    """
    if saltstr is None:
        "TODO: generate the saltstr"
        pass

    return crypt.crypt(rawpass, saltstr)


def getHashedPassWithBcrypt(rawpass, saltstr=None):
    """
    return the hashed value with bcrypt pasword.
    """
    if saltstr is None:
        # TODO: generate the salt.
        pass

    return bcrypt.hashpw(rawpass, saltstr)


_encryptway = {"NOPASSWORD": lambda: True,
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

    :word: A string that's a word which will be used to do hash check, whether
    it's the correct password.
    :hashstr: the hashed string which means the encrpted password at
    /etc/shadow.
    :returns: A list. list[0]: True means match, then list[1] is the hash
    function str, it can be "SHA1", "SHA256", "SHA512", "BCRYPT" etc.
    if list[0]: False means unmatch, then list[1] is an empty string.

    """
    match = False
    hashedway = _getHashedWay(hashstr)
    hashfunc = _encryptway.get(hashedway)
    if hashfunc is not None:
        match = hashfunc(word, hashstr)

    return [match, hashedway]

import crypt

def getHashedPass(pass, saltstr):
    """'
    return the hashed value with crypt password, but it's not support bcrypt. If bcrypt use getHashedPassWithBcrypt function.
    """
    pass
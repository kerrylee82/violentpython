from zipfile import ZipFile


def extractZip(zFilePath, password):
    try:
        zFile = ZipFile(zFilePath)
        zFile.extractall(pwd=password)
        return password
    except Exception as e:
        return


def zipwithdictattack(zFilePath, dicFilePath):
    """The function will try all passwords in dicFilePath to extract the
    zipfile which zFilepath pointed. If matched, return the password.

    :zFilePath: zip file path.
    :dicFilePath: The dictionary file which stored the possible passwords.
    :returns: password if match otherwise, nothing.

    """
    with open(dicFilePath) as dicFile:
        for line in dicFile:
            password = line.strip('\n')
            guess = extractZip(zFilePath, password)
            if guess:
                return guess

    return


if __name__ == "__main__":
    # TODO: write the test block.
    pass

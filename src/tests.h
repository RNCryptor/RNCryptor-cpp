#include <string>
using std::string;

class RNCryptorTests {
	int completedTests;
	int failedTests;
	int nonImplementedTests;
	int passedTests;

	void performDecryptionTest(string functionName, string encrypted, string password);
	void reportSuccess(string functionName, bool success);
	void reportStatus(string functionName, string status);
	void reportStatusNotImplemented(string functionName);

	// RNCryptor Tests
	void testCanDecryptSelfEncryptedDefaultVersion();
	void testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple();
	void testCanDecryptSelfEncryptedVersion0();
	void testCanDecryptSelfEncryptedVersion1();
	void testCanDecryptSelfEncryptedVersion2();
	void testCanDecryptLongText();
	void testCannotUseWithUnsupportedSchemaVersions();

	// RNDecryptor Tests
	void testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock();
	void testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong();
	void testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock();
	void testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks();
	void testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval();
	void testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong();
	void testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval();
	void testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong();
	void testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval();
	void testDecryptingWithBadPasswordFails();

	// RNEncryptor Tests
	void testCanEncryptWithDefaultVersion();
	void testCanEncryptWithVersion0();
	void testCanEncryptWithVersion1();
	void testCanEncryptWithVersion2();
	void testSelfEncryptedVersion0VectorIsVersion0();
	void testSelfEncryptedVersion1VectorIsVersion1();
	void testSelfEncryptedVersion2VectorIsVersion2();

	public:
		RNCryptorTests();
		void run();
};

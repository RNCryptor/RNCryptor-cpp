#include "tests.h"

#include "rndecryptor.h"
#include "rnencryptor.h"

#include <execinfo.h>

#include <string>
using std::string;

#include <iostream>
using std::cout;
using std::endl;

#include <sstream>
using std::stringstream;

static const string IOS_PASSWORD = "mypassword123$!";

static const string PLAINTEXT_V0_LESS_THAN_ONE_BLOCK = "Monkey";
static const string IOS_ENCRYPTED_V0_LESS_THAN_ONE_BLOCK = "AACoGb/5NAItZ9gY0YkCXK0Q7d+1p2mNyFFKIDldCA5QRqX5i9MNpezRS7CDX8jUDKGtIlZU6d8CZQeJAAAAAAAAAAAAAAAA";

static const string PLAINTEXT_V0_EXACTLY_ONE_BLOCK = "O happy day now.";
static const string IOS_ENCRYPTED_V0_EXACTLY_ONE_BLOCK = "AADsM/JbTInOMSm0epc/7MqQ1Ol2Fu/ySnQ0FknhJeTD6GpZo+SF8JDloHN82yZIHrOcJ3vZuXmrCUt3AysLYg6Vpu4KDwAAAAAAAAAAAAAAAA==";

static const string PLAINTEXT_V0_EXACTLY_TWO_BLOCKS = "Earth is round, sun is round too";
static const string IOS_ENCRYPTED_V0_EXACTLY_TWO_BLOCKS = "AAApp4OoYpg4Fz+WSZDbcf5KPJasOkhdCnptrmwVkt58BZi/lnTWoIOf2IhIZhHsvTKYYEJsds6bFL/nZC/GtENusHWFyEw1IdtQ7KFSp8XZEhiAT88AAAAAAAAAAAAAAAA=";

static const string PLAINTEXT_V0_NON_BLOCK_INTERVAL = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...";
static const string IOS_ENCRYPTED_V0_NON_BLOCK_INTERVAL = "AADu55As8qH9KsSR17p1akydMUlbHrsHudMOr/yTj4olfQedJPTZg8hK4ua99zNkj3Nw7Hle1f1onHclWIYoLkWtMVk4Cp96CcxRhaWbBZqAVvTabtVruxcAi+GEB2K4rrmyARxB2QJH9tfz2yTFoFNMln+xOCUm0wAAAAAAAAAAAAAAAA==";

static const string PLAINTEXT_V1_EXACTLY_ONE_BLOCK = "Lorem ipsum dolor sit amet, cons";

static const string PLAINTEXT_V1_NON_BLOCK_INTERVAL = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...";
static const string IOS_ENCRYPTED_V1_NON_BLOCK_INTERVAL = "AQE9u3aB1APkWDRHcfy1cvD3kwwoXUw+8JhtCkZ3xDkSQghIyFoqLgazX3cXBxv3Mj75sSofHoDI35KaFTdXovY3HQYAaQmMdPNvSRVGvlptkyr5LSBMUA3/Uj7lmhnaf515pN8pUbcbOV8RP+oWhXX4iKN009mrcMaX2j1KQz2JfFj8bfpbu9BOtj+1NotIe14=";

static const string PLAINTEXT_V2_EXACTLY_ONE_BLOCK = "Lorem ipsum dolor sit amet, cons";

static const string PLAINTEXT_V2_NON_BLOCK_INTERVAL = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...";
static const string IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL = "AgG8X+ixN6HN9zFnuK1NMJAPntIuC0+WPsmFhGL314zLuq1T9xWDHYzpnzW8EqDz81Amj36+EqrjazQ1gO9ao6bpMwUKdT2xY4ZUrhtCQm3LD2okbEIGjj5dtMJtB3i759WdnmNf8K0ULDWNzNQHPzdNDcEE2BPh+2kRaqVzWyBOzJppJoD5n+WdglS7BEBU+4U=";

RNCryptorTests::RNCryptorTests() {
	this->completedTests = 0;
	this->failedTests = 0;
	this->nonImplementedTests = 0;
	this->passedTests = 0;
}

void RNCryptorTests::run()
{
	try {
		// RNCryptor Tests
		this->testCanDecryptSelfEncryptedDefaultVersion();
		this->testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple();
		this->testCanDecryptSelfEncryptedVersion0();
		this->testCanDecryptSelfEncryptedVersion1();
		this->testCanDecryptSelfEncryptedVersion2();
		this->testCanDecryptLongText();
		this->testCannotUseWithUnsupportedSchemaVersions();

		// RNDecryptor Tests
		this->testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock();
		this->testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong();
		this->testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock();
		this->testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks();
		this->testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval();
		this->testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong();
		this->testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval();
		this->testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong();
		this->testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval();
		this->testDecryptingWithBadPasswordFails();

		// RNEncryptor Tests
		this->testCanEncryptWithDefaultVersion();
		this->testCanEncryptWithVersion0();
		this->testCanEncryptWithVersion1();
		this->testCanEncryptWithVersion2();
		this->testSelfEncryptedVersion0VectorIsVersion0();
		this->testSelfEncryptedVersion1VectorIsVersion1();
		this->testSelfEncryptedVersion2VectorIsVersion2();

		cout << endl;
		if (this->passedTests != this->completedTests) {
			cout << "ERROR (" << this->completedTests << " tests, " << this->passedTests << " passed, " << this->failedTests << " failed, " << this->nonImplementedTests << " unimplemented)" << endl;
		} else {
			cout << "OK (" << this->passedTests << " tests)" << endl;
		}
		cout << endl;

	} catch (std::exception &e) {
		cout << "Exception: " << e.what() << endl;

		void *array[10];
		size_t size;
		size = backtrace(array, 10);
		backtrace_symbols_fd(array, size, 2);
	}
}

// RNCryptor Tests

void RNCryptorTests::testCanDecryptSelfEncryptedDefaultVersion() {

	RNEncryptor *encryptor = new RNEncryptor();
	string encryptedB64 = encryptor->encrypt(PLAINTEXT_V2_NON_BLOCK_INTERVAL, IOS_PASSWORD);
	delete encryptor;

	cout << "Encrypted B64: " << encryptedB64 << endl;

	RNDecryptor *decryptor = new RNDecryptor();
	string plaintext = decryptor->decrypt(encryptedB64, IOS_PASSWORD);
	delete decryptor;
	cout << "Plaintext: " << plaintext << endl;

	this->reportSuccess(__func__, plaintext == PLAINTEXT_V2_NON_BLOCK_INTERVAL);
}

void RNCryptorTests::testCanDecryptSelfEncryptedStringEqualToBlockSizeMultiple() {
	this->reportStatusNotImplemented(__func__);
}
void RNCryptorTests::testCanDecryptSelfEncryptedVersion0() {
	this->reportStatusNotImplemented(__func__);
}
void RNCryptorTests::testCanDecryptSelfEncryptedVersion1() {
	this->reportStatusNotImplemented(__func__);
}
void RNCryptorTests::testCanDecryptSelfEncryptedVersion2() {
	this->reportStatusNotImplemented(__func__);
}
void RNCryptorTests::testCanDecryptLongText() {
	this->reportStatusNotImplemented(__func__);
}
void RNCryptorTests::testCannotUseWithUnsupportedSchemaVersions() {
	this->reportStatusNotImplemented(__func__);
}

// RNDecryptor Tests
void RNCryptorTests::testCanDecryptIosEncryptedVersion0WithPlaintextLengthLessThanOneBlock() {
	this->performDecryptionTest(__func__, IOS_ENCRYPTED_V0_LESS_THAN_ONE_BLOCK, IOS_PASSWORD);
}

void RNCryptorTests::testCanDecryptIosEncryptedVersion0WithPlaintextReallyLong() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyOneBlock() {
	this->performDecryptionTest(__func__, IOS_ENCRYPTED_V0_EXACTLY_ONE_BLOCK, IOS_PASSWORD);
}

void RNCryptorTests::testCanDecryptIosEncryptedVersion0WithPlaintextLengthExactlyTwoBlocks() {
	this->performDecryptionTest(__func__, IOS_ENCRYPTED_V0_EXACTLY_TWO_BLOCKS, IOS_PASSWORD);
}

void RNCryptorTests::testCanDecryptIosEncryptedVersion0WithPlaintextLengthNotOnBlockInterval() {
	this->performDecryptionTest(__func__, IOS_ENCRYPTED_V0_NON_BLOCK_INTERVAL, IOS_PASSWORD);
}

void RNCryptorTests::testCanDecryptIosEncryptedVersion1WithPlaintextReallyLong() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testCanDecryptIosEncryptedVersion1WithPlaintextLengthNotOnBlockInterval() {
	this->performDecryptionTest(__func__, IOS_ENCRYPTED_V1_NON_BLOCK_INTERVAL, IOS_PASSWORD);
}

void RNCryptorTests::testCanDecryptIosEncryptedVersion2WithPlaintextReallyLong() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testCanDecryptIosEncryptedVersion2WithPlaintextLengthNotOnBlockInterval() {
	this->performDecryptionTest(__func__, IOS_ENCRYPTED_V2_NON_BLOCK_INTERVAL, IOS_PASSWORD);
}

void RNCryptorTests::testDecryptingWithBadPasswordFails() {
	RNDecryptor *cryptor = new RNDecryptor();
	string decrypted = cryptor->decrypt(PLAINTEXT_V2_NON_BLOCK_INTERVAL, "bad-password");
	delete cryptor;

	this->reportSuccess(__func__, decrypted == "");
}

// RNEncryptor Tests

void RNCryptorTests::testCanEncryptWithDefaultVersion() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testCanEncryptWithVersion0() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testCanEncryptWithVersion1() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testCanEncryptWithVersion2() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testSelfEncryptedVersion0VectorIsVersion0() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testSelfEncryptedVersion1VectorIsVersion1() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::testSelfEncryptedVersion2VectorIsVersion2() {
	this->reportStatusNotImplemented(__func__);
}

void RNCryptorTests::performDecryptionTest(string functionName, string encrypted, string password)
{
	RNDecryptor *cryptor = new RNDecryptor();
	string decrypted = cryptor->decrypt(encrypted, password);
	delete cryptor;

	this->reportSuccess(functionName, decrypted == PLAINTEXT_V2_NON_BLOCK_INTERVAL);
}

void RNCryptorTests::reportSuccess(string functionName, bool success)
{
	string statusText;
	if (success) {
		this->passedTests++;
		statusText = "OK";

	} else {
		this->failedTests++;
		statusText = "FAILED";
	}
	this->reportStatus(functionName, statusText);
}

void RNCryptorTests::reportStatusNotImplemented(string functionName)
{
	this->reportStatus(functionName, "not implemented");
	this->nonImplementedTests++;
}

void RNCryptorTests::reportStatus(string functionName, string status)
{
	this->completedTests++;

	const int firstColumnWidth = 80;
	stringstream output;
	output << functionName << " ";

	for (int i = functionName.length() + 2; i < firstColumnWidth; i++) {
		output << ".";
	}

	output << " " << status << endl;
	cout << output.str();
}

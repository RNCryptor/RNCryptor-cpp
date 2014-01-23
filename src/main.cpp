#include "tests.h"
#include "rncryptor.h"

#include <iostream>
#include <sstream>
using std::stringstream;

int main () {

	RNCryptorTests *tester = new RNCryptorTests();
	tester->run();

	delete tester;
}


/*
void testCanDecryptSelfEncryptedDefaultVersion() {
  		$encryptor = new RNEncryptor();
  		$encrypted = $encryptor->encrypt(self::SAMPLE_PLAINTEXT, self::SAMPLE_PASSWORD);

  		$decryptor = new RNDecryptor();
  		$decrypted = $decryptor->decrypt($encrypted, self::SAMPLE_PASSWORD);
  		$this->assertEquals(self::SAMPLE_PLAINTEXT, $decrypted);
  	}

	string password = "mypassword123$!";
	string encrypted = "AgG8X+ixN6HN9zFnuK1NMJAPntIuC0+WPsmFhGL314zLuq1T9xWDHYzpnzW8EqDz81Amj36+EqrjazQ1gO9ao6bpMwUKdT2xY4ZUrhtCQm3LD2okbEIGjj5dtMJtB3i759WdnmNf8K0ULDWNzNQHPzdNDcEE2BPh+2kRaqVzWyBOzJppJoD5n+WdglS7BEBU+4U=";
	string expected_plaintext = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do...";

	RNDecryptor *decryptor = new RNDecryptor();
	string plaintext = decryptor->decrypt(encrypted, password);

	cout << "encrypted: " << encrypted << endl;
	cout << "expected:  " << expected_plaintext << endl;
	cout << "actual:    " << plaintext << endl;
	cout << "Status:    " << (expected_plaintext == plaintext ? "Success!" : "Nope") << endl;

	delete decryptor;
}
*/

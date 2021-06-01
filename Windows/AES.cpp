#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cin;
using std::cout;
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;

#include "cryptopp/xts.h"
using CryptoPP::XTS_Mode;

#include "cryptopp/ccm.h"
using CryptoPP::CCM;
// using CryptoPP::CCM_TablesOption;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include "cryptopp/aes.h"
using CryptoPP::AES;
using CryptoPP::byte;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#ifdef _WIN32
	#include <io.h>
	#include <fcntl.h>
#elif __linux__
	#include <stdio_ext.h>
#else
#endif

#include <codecvt>
#include <locale>

#include "assert.h"

void clean_stdin() {
	#ifdef _WIN32
		fflush(stdin);
	#elif __linux__
		__fpurge(stdin);
	#else
	#endif
}

// convert UTF-8 string to wstring
std::wstring utf8_to_wstring (const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// convert wstring to UTF-8 string
std::string wstring_to_utf8 (const std::wstring& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

double AES_ECB_encrypt(SecByteBlock key, string plain, string& cipher) {
	int start = clock();
	try {

		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, key.size());

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_ECB_decrypt(SecByteBlock key, string cipher, string& recovered) {
	int start = clock();
	try	{
		ECB_Mode< AES >::Decryption d;
		// ECB Mode does not use an IV
		d.SetKey( key, key.size() );

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss3( cipher, true, 
			new StreamTransformationFilter( d,
				new StringSink( recovered )
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch( CryptoPP::Exception& e )	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_CBC_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{		

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_CBC_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif
		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_OFB_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{		

		OFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// OFB mode must not use padding. Specifying
		//  a scheme will result in an exception
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_OFB_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_CFB_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{

		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// CFB mode must not use padding. Specifying
		//  a scheme will result in an exception
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_CFB_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_CTR_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{

		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_CTR_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		
	}
	catch(const CryptoPP::Exception& e)	{
		cerr << e.what() << endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_XTS_encrypt(SecByteBlock key, SecByteBlock iv, string plain, string& cipher) {
	int start = clock();
	try	{

		XTS_Mode< AES >::Encryption enc;
		enc.SetKeyWithIV( key, key.size(), iv );

		// The StreamTransformationFilter adds padding
		//  as requiredec. ECB and XTS Mode must be padded
		//  to the block size of the cipher.
		StringSource ss( plain, true, 
			new StreamTransformationFilter( enc,
				new StringSink( cipher ),
				StreamTransformationFilter::NO_PADDING
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch( const CryptoPP::Exception& ex )	{
		std::cerr << ex.what() << std::endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_XTS_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string& recovered) {
	int start = clock();
	try	{
		XTS_Mode< AES >::Decryption dec;
		dec.SetKeyWithIV( key, key.size(), iv );

		// The StreamTransformationFilter removes
		//  padding as requiredec.
		StringSource ss( cipher, true, 
			new StreamTransformationFilter( dec,
				new StringSink( recovered ),
				StreamTransformationFilter::NO_PADDING
			) // StreamTransformationFilter
		); // StringSource

		std::cout << "recovered text: " << recovered << std::endl;
	}
	catch( const CryptoPP::Exception& ex )	{
		std::cerr << ex.what() << std::endl;
		exit(1);
	}
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_GCM_encrypt(SecByteBlock key, SecByteBlock iv, string pdata, string adata, string& cipher, int TAG_SIZE) {
	int start = clock();
	try {
        GCM< AES >::Encryption e;
        e.SetKeyWithIV( key, key.size(), iv, iv.size() );
        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        AuthenticatedEncryptionFilter ef( e,
            new StringSink( cipher ), false, TAG_SIZE
        ); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
        ef.ChannelMessageEnd("");

    }
    catch( CryptoPP::BufferedTransformation::NoChannelSupport& e ) {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e ) {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e ) {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_GCM_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string adata, string& rpdata, int TAG_SIZE) {
	int start = clock();
	try {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV( key, key.size(), iv, iv.size() );

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string mac = cipher.substr( cipher.length()-TAG_SIZE );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
        df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
        df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        assert( true == df.GetLastResult() );

        string retrieved;
        size_t n = (size_t)-1;

        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        rpdata = retrieved;
    }
    catch( CryptoPP::InvalidArgument& e ) {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e ) {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e ) {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_CCM_encrypt(SecByteBlock key, SecByteBlock iv, string pdata, string adata, string& cipher, int TAG_SIZE) {
	int start = clock();
	try {
        CCM< AES >::Encryption e;
        e.SetKeyWithIV( key, key.size(), iv, iv.size() );
        // Not required for GCM mode (but required for CCM mode)
        e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        AuthenticatedEncryptionFilter ef( e,
            new StringSink( cipher ), false, TAG_SIZE
        ); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
        ef.ChannelMessageEnd("");

    }
    catch( CryptoPP::BufferedTransformation::NoChannelSupport& e ) {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e ) {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e ) {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

double AES_CCM_decrypt(SecByteBlock key, SecByteBlock iv, string cipher, string adata, string& rpdata, int TAG_SIZE) {
	int start = clock();
	try {
        CCM< AES >::Decryption d;
        d.SetKeyWithIV( key, key.size(), iv, iv.size() );
        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );		
        string mac = cipher.substr( cipher.length()-TAG_SIZE );
		
		d.SpecifyDataLengths( adata.size(), enc.size(), 0 );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
        df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
        df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        assert( true == df.GetLastResult() );

        string retrieved;
        size_t n = (size_t)-1;

        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        rpdata = retrieved;
    }
    catch( CryptoPP::InvalidArgument& e ) {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e ) {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e ) {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
	int end = clock();
	return (end - start) * 1000.0 / CLOCKS_PER_SEC;
}

int main(int argc, char* argv[]) {
	#ifdef __linux__
		setlocale(LC_ALL,"");
	#elif _WIN32
		_setmode(_fileno(stdin), _O_U16TEXT);
		_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	AutoSeededRandomPool prng;

	SecByteBlock key(16);

	SecByteBlock iv(16);

	//byte iv[AES::BLOCKSIZE];	

	wcout << L"Input plaintext: ";
	wstring utf16plain;
	getline(wcin, utf16plain);
	string plain = wstring_to_utf8(utf16plain);
	string cipher, encoded, recovered, adata, radata;
	int TAG_SIZE = 16;

	//chose mode
	wcout << L"Choose mode:\n";
	wcout << L"1. ECB    2.CBC    3.OFB    4.CFB    5.CTR    6.XTS    7.CCM    8.GCM\n";
	int mode;
	wcin >> mode;
	if (mode <= 0 || mode >= 9) {
		wcout << L"Not valid option\n";
		return 0;
	}	
	
	if (mode == 7 || mode == 8) {
		wcout << L"Input authentication data: ";
		clean_stdin();
		wstring utf16data;
		getline(wcin, utf16data);
		adata = wstring_to_utf8(utf16data);
	}

	// key genarator or input	
	wcout << L"Choose key length\n";
	int tmp;
	if (mode == 6) {
		wcout << "1.256 bit    2.384 bit    3.512 bit\n";		
		wcin >> tmp;
		if (tmp == 1) {
			key.New(32);
		} else if (tmp == 2) {
			key.New(48);
		} else if (tmp == 3) {
			key.New(64);
		} else {
			wcout << L"Not valid option\n";
			return 0;
		}
	} else {
		wcout << "1.128 bit    2.192 bit    3.256 bit\n";		
		wcin >> tmp;
		if (tmp == 1) {
			key.New(16);
		} else if (tmp == 2) {
			key.New(24);
		} else if (tmp == 3) {
			key.New(32);
		} else {
			wcout << L"Not valid option\n";
			return 0;
		}
	}   

   // key genarator or input
	wcout << L"1.Input key from screen    2.Input key from file    3.Random key\n";
	wcin >> tmp;
	if (tmp == 1) {	
		wstring skey;	
		clean_stdin();
		getline(wcin, skey);
		string tmp = wstring_to_utf8(skey);
		if (tmp.size() < key.size()) {
			wcout << "Not enough length!\n";
			return 0;
		}
		for (int i = 0; i < (int)key.size(); i++) {
			key[i] = tmp[i];
		}
	} else if (tmp == 2) {
		wcout << L"Open AES_key.key...\n";
		try {
			FileSource fs("AES_key.key", false);
			CryptoPP::ArraySink copykey(key, key.size());
			fs.Detach(new Redirector(copykey));
			fs.Pump(key.size());
		} catch(const CryptoPP::Exception& e) {
			wcout << L"File AES_key.key not valid\n";
			return 0;
		}
		
	} else if (tmp == 3) {
		prng.GenerateBlock(key, key.size());
	} else {
		wcout << L"Not valid option\n";
		return 0;
	}

	//select iv size for ccm and gcm
	if (mode == 7) { // ccm
		wcout << L"Choose iv size [7->13]: ";
		int size;
		wcin >> size;
		if (size < 7 || size > 13) {
			wcout << L"Iv size not valid\n";
			return 0;
		}
		iv.New(size);
	}

	if (mode == 8) { // gcm
		wcout << L"Choose iv size [1->63]: ";
		int size;
		wcin >> size;
		if (size < 1 && size> 63) {
			wcout << L"Iv size not valid\n";
			return 0;
		}
		iv.New(size);
	}		

	// iv genarator or input
	if (mode != 1) {
		wcout << L"1.Input iv from screen    2.Input iv from file    3.Random iv\n";
		wcin >> tmp;
		if (tmp == 1) {
			wstring skey;	
			clean_stdin();
			getline(wcin, skey);	
			string tmp = wstring_to_utf8(skey);
			if (tmp.size() < iv.size()) {
				wcout << "Not enough length!\n";
				return 0;
			}
			for (int i = 0; i < (int)iv.size(); i++) {
				iv[i] = tmp[i];
			}
		} else if (tmp == 2) {
			wcout << L"Open AES_iv.key...\n";
			try {
				FileSource fs("AES_iv.key", false);
				CryptoPP::ArraySink copykey(iv, iv.size());
				fs.Detach(new Redirector(copykey));
				fs.Pump(iv.size());
			} catch(const CryptoPP::Exception& e) {
				wcout << L"File AES_iv.key not valid\n";
				return 0;
			}			
		} else if (tmp == 3) {
			prng.GenerateBlock(iv, iv.size());
		} else {
			wcout << L"Not valid option\n";
			return 0;
		}
	}

	//select tag size for ccm and gcm
	if (mode == 7) { // ccm
		wcout << L"Choose tag size [4, 6, 8, 10, 12, 14, 16]: ";
		wcin >> TAG_SIZE;
		if (TAG_SIZE % 2 || TAG_SIZE < 4 || TAG_SIZE > 16) {
			wcout << L"Tag size not valid\n";
			return 0;
		}
	}

	if (mode == 8) { // gcm
		wcout << L"Choose tag size [12, 13, 14, 15, 16]: ";
		wcin >> TAG_SIZE;
		if (TAG_SIZE < 12 || TAG_SIZE > 16) {
			wcout << L"Tag size not valid\n";
			return 0;
		}
	}

	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << utf8_to_wstring(encoded) << endl;

	// Pretty print iv
	if (mode != 1) {
		encoded.clear();
		StringSource(iv, iv.size(), true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		wcout << "iv: " << utf8_to_wstring(encoded) << endl;
	}

	double time = 0;

	switch (mode) {
		case 1:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += AES_ECB_encrypt(key, plain, cipher);
			}			
			break;
		case 2:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += AES_CBC_encrypt(key, iv, plain, cipher);
			}			
			break;
		case 3:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += AES_OFB_encrypt(key, iv, plain, cipher);
			}			
			break;
		case 4:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += AES_CFB_encrypt(key, iv, plain, cipher);
			}			
			break;
		case 5:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += AES_CTR_encrypt(key, iv, plain, cipher);
			}			
			break;
		case 6:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += AES_XTS_encrypt(key, iv, plain, cipher);
			}			
			break;
		case 7:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += AES_CCM_encrypt(key, iv, plain, adata, cipher, TAG_SIZE);
			}			
			break;
		default:
			for (int i = 0; i < 10000; i++) {
				cipher.clear();
				time += AES_GCM_encrypt(key, iv, plain, adata, cipher, TAG_SIZE);
			}			
			break;
	}	

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "Cipher text: " << utf8_to_wstring(encoded) << endl;
	wcout << "Time encrypt: " << time / 10000 << "ms\n";

	time = 0;
	
	switch (mode) {
		case 1:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += AES_ECB_decrypt(key, cipher, recovered);
			}			
			break;
		case 2:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += AES_CBC_decrypt(key, iv, cipher, recovered);
			}			
			break;
		case 3:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += AES_OFB_decrypt(key, iv, cipher, recovered);
			}			
			break;
		case 4:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += AES_CFB_decrypt(key, iv, cipher, recovered);
			}			
			break;
		case 5:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += AES_CTR_decrypt(key, iv, cipher, recovered);
			}			
			break;
		case 6:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += AES_XTS_decrypt(key, iv, cipher, recovered);				
			}			
			break;
		case 7:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += AES_CCM_decrypt(key, iv, cipher, adata, recovered, TAG_SIZE);
			}			
			break;
		default:
			for (int i = 0; i < 10000; i++) {
				recovered.clear();
				time += AES_GCM_decrypt(key, iv, cipher, adata, recovered, TAG_SIZE);
			}			
			break;
	}

	wcout << "Recovered text: " << utf8_to_wstring(recovered) << endl;

	if (mode == 7 || mode == 8) {
		wcout << "Authentication data: " << utf8_to_wstring(adata) << endl;
	}
	
	wcout << "Time decrypt: " << time / 10000 << "ms\n";

	wcout << L"1.Save key and iv    2.Exit\n";
	wcin >> tmp;
	if (tmp == 1) {
		StringSource ss1(key, key.size(), true , new FileSink( "AES_key_save.key"));
		if (mode != 1) {
			StringSource ss2(iv, iv.size(), true , new FileSink( "AES_iv_save.key"));
		}		
	}

	return 0;
}

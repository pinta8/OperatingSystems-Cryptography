package os.foi.hr.os2_kriptografija;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

public class MainActivityAsymmetricCrypting extends AppCompatActivity {
    KeyPairGenerator keyPairGenerator;
    KeyPair keyPair;
    PublicKey publicKey;
    PrivateKey privateKey;
    byte[] encryptedBytes, decryptedBytes, encodedPublicKey, encodedPrivateKey, digitalSignature;
    Cipher cipher, cipher1;
    String encrypted, decrypted;
    KeyPairGenerator keyPairGeneratorSign;
    KeyPair keyPairSign;
    Signature signer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main_asymmetric_crypting);
    }

    public void createText(View view) {
        EditText editTextTextToCrypt = findViewById(R.id.editTextToCrypt);
        String inputToCrypt = String.valueOf(editTextTextToCrypt.getText());

        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File file = new File(dir, "text_za_kriptirati.txt");

        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(inputToCrypt);
        } catch (IOException e) {
            e.printStackTrace();
        }
        editTextTextToCrypt.setText("");
    }

    public void getCryptedText(View view) {
        Intent intent = new Intent()
                .setType("*/*")
                .setAction(Intent.ACTION_GET_CONTENT);
        startActivityForResult(Intent.createChooser(intent, "Odabire datoteku čiji ćete tekst kriptirati"), 123);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        EditText editTextDataToCrypt = findViewById(R.id.editTextToCrypt);
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 123 && resultCode == RESULT_OK) {
            try {
                editTextDataToCrypt.setText(readTextFromUri(data.getData()));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String readTextFromUri(Uri uri) throws IOException {
        InputStream inputStream = getContentResolver().openInputStream(uri);
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                inputStream));
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            stringBuilder.append(line);
        }
        inputStream.close();
        return stringBuilder.toString();
    }

    public void encryptAsymmetric(View view) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        EditText editTextDataToCrypt = findViewById(R.id.editTextToCrypt);
        String encryptedText = encryptAsymmetric(editTextDataToCrypt.getText().toString());
        EditText editTextEncryptedData = findViewById(R.id.editTextEncryptedText);
        editTextEncryptedData.setText(encryptedText);

        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File encryptedFile = new File(dir, "kriptirani_text.txt");

        try (FileWriter fileWriter = new FileWriter(encryptedFile)) {
            fileWriter.write(encryptedText);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void decryptAsymmetric(View view) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {

        EditText editTextEncryptedData = findViewById(R.id.editTextEncryptedText);
        String decryptedText = decryptAsymmetric(editTextEncryptedData.getText().toString());
        EditText editTextDecryptedData = findViewById(R.id.editTextDecryptedText);
        editTextDecryptedData.setText(decryptedText);
    }

    public String encryptAsymmetric(String plain) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        keyPair = keyPairGenerator.genKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        encodedPublicKey = publicKey.getEncoded();
        encodedPrivateKey = privateKey.getEncoded();
        writeInFilePublicAndPrivateKey(encodedPublicKey, encodedPrivateKey);

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytesToEncrypt = plain.getBytes("utf-8");
        encryptedBytes = cipher.doFinal(bytesToEncrypt);
        encrypted = Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
        return encrypted;
    }

    public String decryptAsymmetric(String result) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        cipher1 = Cipher.getInstance("RSA");
        cipher1.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytesToDecrypt = Base64.decode(result, Base64.DEFAULT);
        decryptedBytes = cipher1.doFinal(bytesToDecrypt);
        decrypted = new String(decryptedBytes, "utf-8");
        return decrypted;
    }

    private void writeInFilePublicAndPrivateKey(byte[] publicKey, byte[] privateKey) {
        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File filePublicKey = new File(dir, "javni_kljuc.txt");
        File filePrivateKey = new File(dir, "privatni_kljuc.txt");

        String publicKeyToWrite = Base64.encodeToString(publicKey, Base64.DEFAULT);
        String privateKeyToWrite = Base64.encodeToString(privateKey, Base64.DEFAULT);

        try (FileWriter fileWriter = new FileWriter(filePublicKey)) {
            fileWriter.write(publicKeyToWrite);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try (FileWriter fileWriter = new FileWriter(filePrivateKey)) {
            fileWriter.write(privateKeyToWrite);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void makeMessageDigest(View view) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        signer = Signature.getInstance("SHA256WithDSA");
        keyPairGeneratorSign = KeyPairGenerator.getInstance("DSA");
        keyPairSign = keyPairGeneratorSign.generateKeyPair();

        EditText editTextPlainData = findViewById(R.id.editTextToCrypt);
        String textToSign = editTextPlainData.getText().toString();

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(textToSign.getBytes());
        signer.initSign(keyPairSign.getPrivate());
        signer.update(digest);

        digitalSignature = signer.sign();
        String textDigestToWrite = Base64.encodeToString(digest, Base64.DEFAULT);
        String textDigitalSignatureToWrite = Base64.encodeToString(digitalSignature, Base64.DEFAULT);

        writeMessageDigestAndSignatureToFile(textDigestToWrite, textDigitalSignatureToWrite);
    }

    private void writeMessageDigestAndSignatureToFile(String textDigestToWrite, String textDigitalSignatureToWrite) {
        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File digestToWrite = new File(dir, "sazetak_poruke.txt");
        File signatureToWrite = new File(dir, "potpis_poruke.txt");

        try (FileWriter fileWriter = new FileWriter(digestToWrite)) {
            fileWriter.write(textDigestToWrite);
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (FileWriter fileWriter = new FileWriter(signatureToWrite)) {
            fileWriter.write(textDigitalSignatureToWrite);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void checkSignature(View view) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        EditText editTextPlainData = findViewById(R.id.editTextToCrypt);
        String textToCheck = editTextPlainData.getText().toString();

        Signature verifier = Signature.getInstance("SHA256WithDSA");
        byte[] digestVerifyMessage = MessageDigest.getInstance("SHA-256").digest(textToCheck.getBytes());
        verifier.initVerify(keyPairSign.getPublic());
        verifier.update(digestVerifyMessage);
        boolean signatureVerified = verifier.verify(digitalSignature);
        if (signatureVerified) {
            Toast.makeText(getApplicationContext(), "Integritet sadržaja nije ugrožen!", Toast.LENGTH_LONG).show();
        } else
            Toast.makeText(getApplicationContext(), "Integritet sadržaja jest ugrožen!", Toast.LENGTH_LONG).show();
    }
}
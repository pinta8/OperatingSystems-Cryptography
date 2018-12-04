package os.foi.hr.os2_kriptografija;

import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivityAsymmetricCrypting extends AppCompatActivity {
    KeyPairGenerator keyPairGenerator;
    KeyPair keyPair;
    PublicKey publicKey;
    PrivateKey privateKey;
    byte[] encryptedBytes, decryptedBytes;
    Cipher cipher, cipher1;
    String encrypted, decrypted;

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

    public void encryptAsymmetric(View view) throws IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

        EditText editTextDataToCrypt = findViewById(R.id.editTextToCrypt);
        String encryptedText = encryptAsymmetric(editTextDataToCrypt.getText().toString());
        EditText editTextEncryptedData = findViewById(R.id.editTextEncryptedText);
        editTextEncryptedData.setText(encryptedText);
    }

    public void decryptAsymmetric(View view) throws IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {

        EditText editTextEncryptedData = findViewById(R.id.editTextEncryptedText);
       String decryptedText = decryptAsymmetric(editTextEncryptedData.getText().toString());
        EditText editTextDecryptedData = findViewById(R.id.editTextDecryptedText);
        editTextDecryptedData.setText(decryptedText);
    }

    public String encryptAsymmetric(String plain) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        keyPair = keyPairGenerator.genKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytesToEncrypt = Base64.decode(plain, Base64.NO_WRAP);
        encryptedBytes = cipher.doFinal(bytesToEncrypt);
        encrypted = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);
        return encrypted;
    }

    public String decryptAsymmetric(String result) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        cipher1 = Cipher.getInstance("RSA");
        cipher1.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytesToDecrypt = Base64.decode(result, Base64.NO_WRAP);
        decryptedBytes = cipher1.doFinal(bytesToDecrypt);
        decrypted = Base64.encodeToString(decryptedBytes, Base64.NO_WRAP);
        return decrypted;
    }
}
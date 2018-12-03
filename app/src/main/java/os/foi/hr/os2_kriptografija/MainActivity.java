package os.foi.hr.os2_kriptografija;

import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void createText(View view) {
        EditText editTextTextToCrypt = findViewById(R.id.editTextToCrypt);
        String inputToCrypt = String.valueOf(editTextTextToCrypt.getText());

        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File file = new File(dir, "text_za_kriptirati.txt");

        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(inputToCrypt);
        }
        catch (IOException e) {
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
        EditText editTextTextToCrypt = findViewById(R.id.editTextToCrypt);
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 123 && resultCode == RESULT_OK) {
            try {
                editTextTextToCrypt.setText(readTextFromUri(data.getData()));
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

    public void encryptSymmetric(View view) throws NoSuchAlgorithmException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] b = baos.toByteArray();

        byte[] keyStart = "this is a key".getBytes();
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
      //  SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
      //  sr.setSeed(keyStart);
      //  kgen.init(128, sr); // 192 and 256 bits may not be available
        SecretKey skey = kgen.generateKey();
        byte[] key = skey.getEncoded();
        byte[] encryptedData = null;
        try {
            encryptedData = encrypt(key,b);
        } catch (Exception e) {
            e.printStackTrace();
        }

        String inputToCrypt = encryptedData.toString();

        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File file = new File(dir, "kriptirani_text.txt");

        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(inputToCrypt);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        EditText editTextEncryptedText = findViewById(R.id.editTextEncryptedText);
        editTextEncryptedText.setText(inputToCrypt);
    }

    private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
    }

    private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }

    public void decryptSymmetric(View view) {
        EditText editTextEncryptedText = findViewById(R.id.editTextEncryptedText);
        editTextEncryptedText.setText(inputToCrypt);
        byte[] decryptedData = decrypt(key,encryptedData);
    }
}
package os.foi.hr.os2_kriptografija;

import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

    }

    public void createText(View view) {
        EditText editTextTextToCrypt = findViewById(R.id.editTextToCrypt);
        editTextTextToCrypt = findViewById(R.id.editTextToCrypt);
        String inputToCrypt = String.valueOf(editTextTextToCrypt.getText());

        File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        File file = new File(dir, "text_za_kriptirati.txt");

        try (FileWriter fileWriter = new FileWriter(file)) {
            fileWriter.write(inputToCrypt);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
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
            Uri selectedfile = data.getData(); //The uri with the location of the file
           // String pathToFile = selectedfile.getEncodedPath();
//            String pathFile = String.valueOf(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS));
//            String absolutePath = pathFile + selectedfile.getLastPathSegment();

            File file = new File (selectedfile.getPath());
            InputStream inputStream = null;
            try {
                inputStream = new FileInputStream(file);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
//            try {
//                inputStream = getApplicationContext().openFileInput(selectedfile.getLastPathSegment());
//            } catch (FileNotFoundException e) {
//                e.printStackTrace();
//            }

            if ( inputStream != null ) {
                InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
                BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
                String receiveString = "";
                StringBuilder stringBuilder = new StringBuilder();

                try {
                while ( (receiveString = bufferedReader.readLine()) != null ) {
                    stringBuilder.append(receiveString);
                }
                inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                editTextTextToCrypt.setText(stringBuilder.toString());
            }
        }
    }
}
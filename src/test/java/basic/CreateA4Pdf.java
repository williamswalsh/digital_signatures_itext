package basic;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfWriter;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CreateA4Pdf {

    public static final String FILE_PATH = "results/hello.pdf";

    @Test
    public void createA4PdfTest() throws IOException, DocumentException {
        Document document = new Document();
        PdfWriter.getInstance(document, Files.newOutputStream(Paths.get(FILE_PATH)));
        document.open();
        document.add(new Paragraph(
                "GPS: 52.46060906351363, -9.750502764491772"));
        document.close();
    }
}

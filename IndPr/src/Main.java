import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Stack;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.yaml.snakeyaml.Yaml;
import java.util.Map;
import java.util.HashMap;
import javax.swing.*;

public class Main {
	
    // Метод для проверки, является ли символ оператором
	public static boolean isOperator(char c) {
    return c == '+' || c == '-' || c == '*' || c == '/' || c == '~';
}

	// Метод для проверки правильности выражения
	public static boolean isValidExpression(String expr) {
    Stack<Character> stack = new Stack<>();
    boolean lastWasOperator = true;

    for (int i = 0; i < expr.length(); i++) {
        char c = expr.charAt(i);

        if (c == ' ') continue;

        if (c == '(') {
            stack.push(c);
            lastWasOperator = true; // последующий символ может быть числом или открывающей скобкой
        } else if (c == ')') {
            if (stack.isEmpty() || stack.pop() != '(') {
                return false; // несоответствующая закрывающая скобка
            }
            lastWasOperator = false; // после закрывающей скобки не может идти оператор
        } else if (Character.isDigit(c) || c == '.') {
            lastWasOperator = false; // после числа может идти оператор или закрывающая скобка
        } else if (isOperator(c)) {
            if (lastWasOperator) {
                return false; // два оператора подряд
            }
            lastWasOperator = true; // последний символ оператор
        } else {
            return false; // недопустимый символ
        }
    }
    return stack.isEmpty() && !lastWasOperator; // проверяем, что все скобки закрыты и выражение не заканчивается оператором
}

	// Метод для выполнения операций
	public static double performOperation(char operator, double a, double b) {
    switch (operator) {
        case '+':
            return a + b;
        case '-':
            return a - b;
        case '*':
            return a * b;
        case '/':
            if (b == 0) {
                throw new UnsupportedOperationException("Cannot divide by zero");
            }
            return a / b;
        case '~':
            return -a;
        default:
            throw new UnsupportedOperationException("Unsupported operator: " + operator);
    }
}
    
	// Приоретет операций
    public static int getPriority(char operator) {
        switch (operator) {
            case '*':
            case '/':
                return 2;
            case '+':
            case '-':
                return 1;
            case '~':
                return 3;
        }
        return 0;
    }

	// Обработка выражений и вычисление результата
	public static double evaluateExpression(String expr) {
	    Stack<Double> values = new Stack<>();
	    Stack<Character> operators = new Stack<>();
	    int unaryMinusCount = 0;
	
	    for (int i = 0; i < expr.length(); i++) {
	        char c = expr.charAt(i);
	
	        if (c == ' ') continue;
	
	        // Обработка чисел
	        if (Character.isDigit(c) || c == '.') {
	            StringBuilder sb = new StringBuilder();
	            while (i < expr.length() && (Character.isDigit(expr.charAt(i)) || expr.charAt(i) == '.')) {
	                sb.append(expr.charAt(i));
	                i++;
	            }
	            i--;
	            values.push(Double.parseDouble(sb.toString()));
	            
	            for (int j = 0; j < unaryMinusCount; j++) {
	                values.push(values.pop() * -1);
	            }
	            unaryMinusCount = 0;
	        } 
	        else if (c == '(') {
	            operators.push(c);
	        } 
	        else if (c == ')') {
	            while (!operators.isEmpty() && operators.peek() != '(') {
	                double val2 = values.pop();
	                double val1 = values.pop();
	                char op = operators.pop();
	                values.push(performOperation(op, val1, val2));
	            }
	            operators.pop();
	        } 
	        else if (c == '~') {
	            unaryMinusCount++;
	        } 
	        else if (isOperator(c)) {
	            // Обработка операторов
	            while (!operators.isEmpty() && isOperator(operators.peek()) && getPriority(c) <= getPriority(operators.peek())) {
	                double val2 = values.pop();
	                double val1 = values.pop();
	                char op = operators.pop();
	                values.push(performOperation(op, val1, val2));
	            }
	            operators.push(c);
	        }
	    }
	
	    // Обработка оставшихся операторов
	    while (!operators.isEmpty()) {
	        double val2 = values.pop();
	        double val1 = values.pop();
	        char op = operators.pop();
	        values.push(performOperation(op, val1, val2));
	    }
	    return values.pop();
	}

	// Метод для извлечения выражений
	public static List<String> extractExpressions(String expr) {
	    List<String> extractedExpressions = new ArrayList<>();
	    StringBuilder current = new StringBuilder();
	
	    for (char c : expr.toCharArray()) {
	        // Проверка допустимых символов
	        if (Character.isDigit(c) || isOperator(c) || c == '~' || c == '.' || c == ' ' || c == '(' || c == ')') {
	            current.append(c);
	        } else {
	            if (current.length() > 0) {
	                extractedExpressions.add(current.toString().trim());
	                current.setLength(0);
	            }
	        }
	    }
	    // Добавление оставшегося выражения
	    if (current.length() > 0) {
	        extractedExpressions.add(current.toString().trim());
	    }
	    return extractedExpressions;
	}

	// Метод для извлечения выражений с использованием регулярных выражений
	public static List<String> extractExpressionsUsingRegex(String expr) {
    List<String> expressions = new ArrayList<>();
    String regex = "[0-9]+(\\.[0-9]+)?|[+\\-*/~()]|\\s+";
    Pattern pattern = Pattern.compile(regex);
    Matcher matcher = pattern.matcher(expr);

    while (matcher.find()) {
        String match = matcher.group();
        if (!match.trim().isEmpty() && !match.trim().equals(" ")) {
            expressions.add(match.trim());
        }
    }
    return expressions;
}
    
    private static String readExpressionFromFile(String fileName) throws IOException {
        StringBuilder sb = new StringBuilder();
        
        if (fileName.endsWith(".txt") || fileName.endsWith(".xml") || fileName.endsWith(".json") || fileName.endsWith(".html") || fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
            try (FileReader input = new FileReader(fileName)) {
                // Обработка для YAML
                if (fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
                    Yaml yaml = new Yaml();
                    try (FileReader reader = new FileReader(fileName)) {
                        Map<String, String> data = yaml.load(reader);
                        return data.get("expr"); 
                    }
                }
                // Обработка для HTML
                else if (fileName.endsWith(".html")) {
                    int i;
                    while ((i = input.read()) != -1) {
                        sb.append((char) i);
                    }
                    String html = sb.toString();
                    int start = html.indexOf("<expr>") + "<expr>".length();
                    int end = html.indexOf("</expr>");
                    if (start > -1 && end > -1) {
                        return html.substring(start, end);
                    } else {
                        throw new IllegalArgumentException("<expr> tag not found in HTML file.");
                    }
                } 
                // Обработка для XML
                else if (fileName.endsWith(".xml")) {
                    int i;
                    while ((i = input.read()) != -1) {
                        sb.append((char) i);
                    }
                    String xml = sb.toString();
                    int start = xml.indexOf("<expr>") + "<expr>".length();
                    int end = xml.indexOf("</expr>");
                    return xml.substring(start, end);
                } 
                // Обработка для JSON
                else if (fileName.endsWith(".json")) {
                    int i;
                    while ((i = input.read()) != -1) {
                        sb.append((char) i);
                    }
                    String json = sb.toString();
                    int start = json.indexOf("\"expr\":") + "\"expr\":".length();
                    int end = json.indexOf("}");
                    return json.substring(start, end).replace("\"", "").trim();
                } 
                // Обработка для текстового файла
                else {
                    int i;
                    while ((i = input.read()) != -1) {
                        sb.append((char) i);
                    }
                    return sb.toString();
                }
            }
        } else {
            throw new IllegalArgumentException("Invalid file format. Only .txt, .xml, .json, .html, .yaml and .yml are supported.");
        }
    }
    
    private static void processExpressions(List<String> expressions, StringBuilder output) {
        for (String expression : expressions) {
            if (isValidExpression(expression)) {
                double result = evaluateExpression(expression);
                output.append(expression).append(" = ").append(result).append("\n");
            } else {
                output.append(expression).append(" is invalid\n");
            }
        }
    }

    private static void writeOutputFiles(String output, String fileType) throws IOException {
        switch (fileType) {
            case "TXT":
                try (FileWriter outputTXT = new FileWriter("output.txt")) {
                    outputTXT.write(output);
                }
                break;
            case "XML":
                try (FileWriter outputXML = new FileWriter("output.xml")) {
                    outputXML.write("<results>\n" + output + "\n</results>");
                }
                break;
            case "JSON":
                try (FileWriter outputJSON = new FileWriter("output.json")) {
                    outputJSON.write("{\"results\": \"" + output.replace("\n", "\\n").replace("\"", "\\\"") + "\"}");
                }
                break;
            case "HTML":
                try (FileWriter outputHTML = new FileWriter("output.html")) {
                    outputHTML.write("<html>\n<head>\n<title>Output Results</title>\n</head>\n<body>\n");
                    outputHTML.write("<h1>Output Results</h1>\n<pre>\n");
                    outputHTML.write(output);
                    outputHTML.write("</pre>\n</body>\n</html>");
                }
                break;
            case "YAML":
                writeOutputYaml(output);
                break;
            default:
                throw new IllegalArgumentException("Unsupported file type.");
        }
    }
    
    private static void writeOutputYaml(String output) throws IOException {
        Yaml yaml = new Yaml();
        Map<String, String> data = new HashMap<>();
        data.put("results", output);
        
        try (FileWriter writer = new FileWriter("output.yaml")) {
            yaml.dump(data, writer);
        }
    }

    private static void archiveOutputFiles(Scanner scanner) throws IOException {
        System.out.print("Do you want to archive the output files? (y/n): ");
        String archiveChoice = scanner.nextLine();
        if (archiveChoice.equalsIgnoreCase("y")) {
            try (ZipOutputStream zipOutput = new ZipOutputStream(new FileOutputStream("output.zip"))) {
                addFileToZip(zipOutput, "output.txt");
                addFileToZip(zipOutput, "output.xml");
                addFileToZip(zipOutput, "output.json");
            }
        }
    }

    private static void addFileToZip(ZipOutputStream zipOutput, String fileName) throws IOException {
        zipOutput.putNextEntry(new ZipEntry(fileName));
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) >= 0) {
                zipOutput.write(buffer, 0, length);
            }
        }
        zipOutput.closeEntry();
    }
    
    private static void archiveFile(String fileName) throws IOException {
        String zipFileName = fileName.substring(0, fileName.lastIndexOf('.')) + ".zip";
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFileName));
             FileInputStream fis = new FileInputStream(fileName)) {
             
            ZipEntry zipEntry = new ZipEntry(fileName);
            zos.putNextEntry(zipEntry);

            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) >= 0) {
                zos.write(buffer, 0, length);
            }
            zos.closeEntry();
        }
    }

    private static void encryptOutputFiles(Scanner scanner) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        System.out.print("Do you want to encrypt the output files? (y/n): ");
        String encryptChoice = scanner.nextLine();
        if (encryptChoice.equalsIgnoreCase("y")) {
            String password = "qwerty";
            byte[] salt = { (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32, (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03 };
            int iterationCount = 19;

            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
            pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
            
            encryptFile("output.txt", pbeCipher);
            encryptFile("output.xml", pbeCipher);
            encryptFile("output.json", pbeCipher);
            encryptFile("output.html", pbeCipher);
            encryptFile("output.yaml", pbeCipher);
        }
    }

    private static void encryptFile(String fileName, Cipher cipher) throws IOException {
        try (FileInputStream fis = new FileInputStream(fileName);
             FileOutputStream fos = new FileOutputStream("encrypted_" + fileName);
             CipherOutputStream cipherOutput = new CipherOutputStream(fos, cipher)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) >= 0) {
                cipherOutput.write(buffer, 0, length);
            }
        }
    }
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        // Создание графического интерфейса
        JFrame frame = new JFrame("My Expression");
        frame.setSize(400, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(null);

        JLabel fileNameLabel = new JLabel("Enter the file name:");
        fileNameLabel.setBounds(10, 10, 200, 25);
        frame.add(fileNameLabel);

        JTextField fileNameField = new JTextField();
        fileNameField.setBounds(10, 40, 280, 25);
        frame.add(fileNameField);

        JCheckBox archiveCheckBox = new JCheckBox("Archive output files");
        archiveCheckBox.setBounds(10, 70, 200, 25);
        frame.add(archiveCheckBox);

        JCheckBox encryptCheckBox = new JCheckBox("Encrypt output files");
        encryptCheckBox.setBounds(10, 100, 200, 25);
        frame.add(encryptCheckBox);

        // JComboBox для выбора формата выходного файла
        String[] fileTypes = { "TXT", "XML", "JSON", "HTML", "YAML" };
        JComboBox<String> fileTypeComboBox = new JComboBox<>(fileTypes);
        fileTypeComboBox.setBounds(300, 70, 80, 25);
        frame.add(fileTypeComboBox);

        JButton evaluateButton = new JButton("Enter");
        evaluateButton.setBounds(300, 40, 80, 25);
        frame.add(evaluateButton);

        // JTextArea для отображения выражения
        JTextArea expressionArea = new JTextArea();
        expressionArea.setBounds(10, 130, 370, 60);
        expressionArea.setEditable(false);
        expressionArea.setBorder(BorderFactory.createTitledBorder("Expression"));
        JScrollPane expressionScrollPane = new JScrollPane(expressionArea);
        expressionScrollPane.setBounds(10, 130, 370, 60);
        frame.add(expressionScrollPane);

        // JTextArea для отображения результатов
        JTextArea resultArea = new JTextArea();
        resultArea.setBounds(10, 200, 370, 200);
        resultArea.setEditable(false);
        resultArea.setBorder(BorderFactory.createTitledBorder("Results"));
        JScrollPane resultScrollPane = new JScrollPane(resultArea);
        resultScrollPane.setBounds(10, 200, 370, 200);
        frame.add(resultScrollPane);

        evaluateButton.addActionListener(e -> {
            try {
                String fileName = fileNameField.getText();
                String expr = readExpressionFromFile(fileName);

                expressionArea.setText(expr);

                if (expr == null || !isValidExpression(expr)) {
                    resultArea.setText("Invalid expression.");
                    return;
                }

                // Извлечение выражений
                List<String> expressions = extractExpressions(expr);
                StringBuilder output = new StringBuilder();
                processExpressions(expressions, output);

                // Запись в выходной файл в выбранном формате
                String selectedFileType = (String) fileTypeComboBox.getSelectedItem();
                String outputFileName = "output." + selectedFileType.toLowerCase();
                writeOutputFiles(output.toString(), selectedFileType);

                // Архивация выходного файла, если установлен флажок
                if (archiveCheckBox.isSelected()) {
                    archiveFile(outputFileName);
                    resultArea.append("\nOutput file archived.");
                }

                resultArea.setText("Results written to " + selectedFileType + " format:\n" + output.toString());

             // Проверяем, нужно ли шифровать файлы
                if (encryptCheckBox.isSelected()) {
                    String password = "qwerty";
                    byte[] salt = { (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32, (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03 };
                    int iterationCount = 19;

                    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
                    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
                    SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
                    SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

                    Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
                    pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

                    encryptFile("output." + selectedFileType.toLowerCase(), pbeCipher);
                    resultArea.append("\nOutput file encrypted.");
                }

            } catch (Exception ex) {
                resultArea.setText("Error: " + ex.getMessage());
            }
        });

        frame.setVisible(true);
    }
}
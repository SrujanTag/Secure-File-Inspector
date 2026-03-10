import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class Secure_File_Inspector 
{
    static ArrayList<FileRecord> filelist=new ArrayList<>();
    static ArrayList<SecurityPattern> patterns=new ArrayList<>();
    static Scanner input=new Scanner(System.in);




    static class SecurityPattern 
    {
        String name;
        String regex;
        String riskLevel; 

        public SecurityPattern(String n,String r,String l) 
        {
            name=n;
            regex=r;
            riskLevel=l;
        }
    }





    static class FileRecord 
    {
        File file;
        String name;
        long size;
        String ext;
        String category;
        String status;

        public FileRecord(File f,String n,long s,String e,String c,String st) 
        {
            file=f;
            name=n;
            size=s;
            ext=e;
            category=c;
            status=st;
        }
    }






    public static void main(String[] args) 
    {
        patterns.add(new SecurityPattern("Email Address","[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}","PII_HIGH"));
        patterns.add(new SecurityPattern("IPv4 Address","\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b","PII_MEDIUM"));
        patterns.add(new SecurityPattern("Phone Number","\\b\\d{10}","PII_MEDIUM"));

        patterns.add(new SecurityPattern("Java Runtime","Runtime\\.getRuntime\\(\\)\\.exec","MALICIOUS_HIGH"));
        patterns.add(new SecurityPattern("ProcessBuilder","ProcessBuilder","MALICIOUS_HIGH"));
        patterns.add(new SecurityPattern("CMD Exec","cmd\\.exe","MALICIOUS_HIGH"));
        patterns.add(new SecurityPattern("PowerShell","powershell","MALICIOUS_HIGH"));
        patterns.add(new SecurityPattern("Eval Func","eval\\(","MALICIOUS_MEDIUM"));
        patterns.add(new SecurityPattern("Base64 Decode","base64_decode","MALICIOUS_MEDIUM"));

        while(true) 
        {
            System.out.println("\n=== Secure File Inspector ===");
            System.out.println("1.Scan Directory");
            System.out.println("2.Delete Infected File");
            System.out.println("3.Export Log");
            System.out.println("4.Exit");
            System.out.print("Choice: ");
            String choice=input.nextLine();

            if(choice.equals("1")) 
            {
                scanfolder();
            }
            else if(choice.equals("2")) 
            {
                deletefile();
            }
            else if(choice.equals("3")) 
            {
                exportfile();
            }
            else if(choice.equals("4")) 
            {
                break;
            }
        }
    }






    public static void scanfolder() 
    {
        System.out.print("Enter path : ");
        String path=input.nextLine();
        File folder=new File(path);

        if(folder.exists()==false) 
        {
            System.out.println("Invalid folder.");
            return;
        }

        filelist.clear();
        File[] files=folder.listFiles();

        System.out.println("\n----------------------------------------------------------------------------------------------------");
        System.out.printf("%-20s | %-10s | %-6s | %-20s | %-20s%n","NAME","SIZE","TYPE","CATEGORY","STATUS");
        System.out.println("----------------------------------------------------------------------------------------------------");

        if(files!=null) 
        {
            for(File file:files) 
            {
                if(file.isFile()) 
                {
                    checkfile(file);
                }
            }
        }
        System.out.println("----------------------------------------------------------------------------------------------------");
    }






    public static void checkfile(File file) 
    {
        String name=file.getName();
        String ext=getext(name);
        long size=file.length();
        String category="General"; 
        String status="Safe";      

        try{
            BufferedReader reader=new BufferedReader(new FileReader(file));
            String line;
            while((line=reader.readLine())!=null) 
            {
                for(SecurityPattern p:patterns) 
                {
                    Pattern regex=Pattern.compile(p.regex);
                    Matcher m=regex.matcher(line);

                    if(m.find()) 
                    {
                        if(p.riskLevel.startsWith("PII")) 
                        {
                            category="SENSITIVE";
                        }
                        if(p.riskLevel.startsWith("MALICIOUS")) 
                        {
                            status="INFECTED: "+p.name;
                        }
                    }
                }
                if(status.equals("Safe")==false && category.equals("General")==false) 
                {
                    break;
                }
            }
            reader.close();
        } 
        catch(Exception e) 
        {
            status="Read Error";
        }

        filelist.add(new FileRecord(file,name,size,ext,category,status));
        System.out.printf("%-20s | %-10d | %-6s | %-20s | %-20s%n",shorten(name),size,ext,category,status);
    }






    public static void deletefile() 
    {
        System.out.print("Enter name of infected file to delete: ");
        String target=input.nextLine();
        for(int i=0;i<filelist.size();i++) 
        {
            FileRecord rec=filelist.get(i);
            if(rec.name.equals(target)) 
            {
                if(rec.status.startsWith("INFECTED")) 
                {
                    if(rec.file.delete()) 
                    {
                        System.out.println("Deleted!");
                        filelist.remove(i);
                    } 
                    else 
                    {
                        System.out.println("Permission denied.");
                    }
                } 
                else 
                {
                    System.out.println("File is not infected");
                }
                return;
            }
        }
        System.out.println("File not found in list.");
    }






    public static void exportfile() 
    {
        try {
            FileWriter report=new FileWriter("Scan_Report.csv");
            report.write("Name,Size,Type,Category,Status\n");
            for(FileRecord rec:filelist) 
            {
                report.write(rec.name+","+rec.size+","+rec.ext+","+rec.category+","+rec.status+"\n");
            }
            report.close();
            System.out.println("Saved to Scan_Report.csv");
        } 
        catch(Exception e) 
        {
            System.out.println("Error saving file.");
        }
    }






    public static String getext(String str) 
    {
        int i=str.lastIndexOf('.');
        if(i > 0) 
        {
            return str.substring(i + 1);
        } 
        else 
        {
            return "file";
        }
    }






    public static String shorten(String s) 
    {
        if(s.length()>18) 
        {
            return s.substring(0,15)+"...";
        }
        return s;
    }
}

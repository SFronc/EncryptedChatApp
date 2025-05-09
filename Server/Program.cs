using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using SharedLibrary.Models;
using System.Security.Cryptography;

public class SocketListener
{
    public static bool koniec = false;
    //private Dictionary<string, string> kluczePubliczneKlientow = new Dictionary<string, string>(); //nick,kluczSym
    private Dictionary<string, WatekKlientaTCP> watkiKlientow = new Dictionary<string, WatekKlientaTCP>();
    private Dictionary<WatekKlientaTCP, HashSet<WatekKlientaTCP>> polaczenia = new Dictionary<WatekKlientaTCP, HashSet<WatekKlientaTCP>>();  //klucz to dane polaczenie a wartosc to zbior polaczen z ktorymi jest polaczony klucz
    //private Dictionary<string, HashSet<string>> oczekujacy = new Dictionary<string, HashSet<string>>(); //słownik oczekujących na accept przez drugiego clienta. Zbiór hashset to zbiór oczekujących wobec których dany klient może użyć komendy acc <nick>
    public void Zakoncz(){
        try{
            Console.WriteLine("Kończenie pracy serwera");
            lock(workerThreads){
                foreach(WatekKlientaTCP wt in workerThreads){
                    wt.ZakonczPolaczenie();
                }
            }
            listener.Shutdown(SocketShutdown.Both);
            listener.Close();
        }
        catch{}
        koniec = true;
    }

    List<WatekKlientaTCP> workerThreads = new List<WatekKlientaTCP>();

    public static int Main(String[] args){
        SocketListener sl = new SocketListener();
        Task watekSerwera = new Task(sl.StartServer);
        watekSerwera.Start();

        koniec = false;

        while(!koniec){
            Task.Delay(100).Wait();
        }
        return 0;
    }

    public void UsunWorkera(WatekKlientaTCP wt){
        lock(workerThreads){
            if(workerThreads.Contains(wt))
                Console.WriteLine($"[{wt.Name}]: rozłączył się!");
                foreach(WatekKlientaTCP klient in polaczenia[wt]){
                    klient.WyslijWiadomosc(8, Encoding.UTF8.GetBytes(wt.nazwa));
                }
                workerThreads.Remove(wt);
                watkiKlientow.Remove(wt.nazwa);
        }
    }

    private string WyswietlZawartosc(string path){
        string response = "========== Jesteś w: " + path + " ==========\n";
        response += "Katalogi: \n";
        foreach(string dir in Directory.GetDirectories(path)){
            response += dir + "\n";
        }

        response += "Pliki: \n";
        foreach(string file in Directory.GetFiles(path)){
            response += file + "\n";
        }

        return response;
    }

    public void OdebranaWiadomosc(int kod, byte[] abc, WatekKlientaTCP wt){
        //Console.WriteLine("==================Odebrano: "+kod);
        string nick = "";
        WatekKlientaTCP watekDrugiegoKlienta;
        lock(watkiKlientow){
            switch(kod){
                case 0:
                    if(watkiKlientow.ContainsKey(Encoding.UTF8.GetString(abc))){
                        wt.WyslijWiadomosc(0, Encoding.UTF8.GetBytes("rejected"));
                        UsunWorkera(wt);
                    }
                    else{
                        watkiKlientow.Add(Encoding.UTF8.GetString(abc),wt);
                        wt.WyslijWiadomosc(0, Encoding.UTF8.GetBytes("accepted"));
                        wt.nazwa = Encoding.UTF8.GetString(abc);
                        Console.WriteLine($"[{wt.Name}]: zarejestrowano nick: {Encoding.UTF8.GetString(abc)}");
                        polaczenia[wt] = new HashSet<WatekKlientaTCP>();
                    }
                break;
                case 2:
                    nick = Encoding.UTF8.GetString(abc);
                    if(!watkiKlientow.ContainsKey(nick)){ wt.WyslijWiadomosc(2, Encoding.UTF8.GetBytes("notFound")); return; }
                    if(wt.polaczenia.Contains(nick)){ wt.WyslijWiadomosc(2, Encoding.UTF8.GetBytes("alreadyConnected")); return; }
                    watekDrugiegoKlienta = watkiKlientow[nick];
                    watekDrugiegoKlienta.WyslijWiadomosc(5, Encoding.UTF8.GetBytes(wt.nazwa));
                    /*lock(oczekujacy){
                        oczekujacy[watekDrugiegoKlienta.nazwa].Add(wt.nazwa);
                    }*/
                    watekDrugiegoKlienta.oczekujacy.Add(wt.nazwa);
                break;
                case 1:
                    if(watkiKlientow.ContainsKey(Encoding.UTF8.GetString(abc))){
                        wt.WyslijWiadomosc(1, Encoding.UTF8.GetBytes("true"));
                    }
                    else wt.WyslijWiadomosc(1, Encoding.UTF8.GetBytes("false"));
                break;
                case 4:
                    wt.kluczPubliczny = Encoding.UTF8.GetString(abc);
                break;
                case 5:
                    nick = Encoding.UTF8.GetString(abc);
                        if(!wt.oczekujacy.Contains(nick)){
                            wt.WyslijWiadomosc(7, new byte[1]);
                        }
                        else{
                            //wysyłanie klucza symetrycznego do dwóch klientów
                            watekDrugiegoKlienta = watkiKlientow[nick];
                            
                            byte[] kluczSym = WygenerujKluczSymetryczny(); //tak naprawde to bajty salt (8) + initVector (16) + haslo (32)

                            wt.WyslijWiadomosc(102, kluczSym);
                            watekDrugiegoKlienta.WyslijWiadomosc(102, kluczSym);
                            lock(polaczenia){
                                polaczenia[wt].Add(watekDrugiegoKlienta);
                            }
                        }
                    
                    //byte[] klucz = WygenerujKluczSymetryczny(32);  //32 bajty, 256 bitow
                    //if(!watkiKlientow.ContainsKey(Encoding.UTF8.GetString(abc))){ return; }
                    
                break;
                case 6:
                    wt.WyslijWiadomosc(101, abc);
                break;
                case 7:
                    nick = Encoding.UTF8.GetString(abc);
                    
                    watekDrugiegoKlienta = watkiKlientow[nick];
                    /*lock(oczekujacy){
                        oczekujacy[watekDrugiegoKlienta.nazwa].Remove(wt.nazwa);
                    }*/
                    watekDrugiegoKlienta.oczekujacy.Remove(wt.nazwa);
                break;
                case 8:
                    watekDrugiegoKlienta = watkiKlientow[Encoding.UTF8.GetString(abc)];
                    watekDrugiegoKlienta.WyslijWiadomosc(9, abc);
                break;
                case 20:
                    int dlugoscNicku = BitConverter.ToInt32(abc, 0);
                    byte[] bajtyOdbiorcy = new byte[dlugoscNicku];
                    Buffer.BlockCopy(abc, 4, bajtyOdbiorcy, 0, dlugoscNicku);
                    nick = Encoding.UTF8.GetString(bajtyOdbiorcy);

                    if(watkiKlientow.ContainsKey(nick)){
                        watekDrugiegoKlienta = watkiKlientow[nick];
                        
                        //Podmiana przed wysłaniem nicku odbiorcy na nick nadawcy
                        byte[] noweDane = PodmienNick(nick, wt.nazwa, abc);

                        watekDrugiegoKlienta.WyslijWiadomosc(3, noweDane);
                    }
                break;
            }
        }
        /*Console.WriteLine("["+wt.Name+"]: "+abc);
        var response = ObslozWiadomosc(abc);
        wt.WyslijWiadomosc(response);

        if(response.Equals("Wymuszanie zatrzymania połączenia...")){
            UsunWorkera(wt);
            wt.ZakonczPolaczenie();
            Zakoncz();
        }*/

    }
    Socket ?listener = null;

    public void StartServer(){

        IPHostEntry host = Dns.GetHostEntry("localhost");
        IPAddress ipAdress = host.AddressList[0];
        IPEndPoint localEndPoint = new IPEndPoint(ipAdress, 11000);

        try{
            listener = new Socket(ipAdress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(localEndPoint);

            listener.Listen(10);

            Console.WriteLine("Serwer czeka na nowe połączenia");

            while(!koniec){
                Socket handler = listener.Accept();
                WatekKlientaTCP wt = new WatekKlientaTCP(handler, OdebranaWiadomosc, UsunWorkera);
                Console.WriteLine($"[{wt.Name}]: odebrano połączenie");
                Task t = new Task(wt.Start);
                t.Start();
                workerThreads.Add(wt);
            }
        }
        catch(Exception e){
            Console.WriteLine(e.ToString());
        }
    }

    /*private byte[] WygenerujKluczSymetryczny (int n){
        byte[] klucz = new byte[n];
        RandomNumberGenerator.Fill(klucz);
        return klucz;

    }*/

    private byte[] WygenerujKluczSymetryczny(){
        byte[] salt = RandomNumberGenerator.GetBytes(8);
        byte[] initVector = RandomNumberGenerator.GetBytes(16);
        byte[] haslo = new byte[32];
        using (var rng = RandomNumberGenerator.Create()){
            rng.GetBytes(haslo);
        }

        byte[] output = new byte[salt.Length + initVector.Length + haslo.Length];
        Buffer.BlockCopy(salt, 0, output, 0, salt.Length);
        Buffer.BlockCopy(initVector, 0, output, salt.Length, initVector.Length);
        Buffer.BlockCopy(haslo, 0, output, salt.Length + initVector.Length, haslo.Length);

        return output;
    }

    private byte[] PodmienNick(string obecny, string nowy, byte[] dane){
        byte[] nowyNickBytes = Encoding.UTF8.GetBytes(nowy);
        byte[] nowaDlugoscNicku = BitConverter.GetBytes(nowyNickBytes.Length);

        int staraDlugoscNicku = Encoding.UTF8.GetBytes(obecny).Length;

        int offsetReszty = 4 + staraDlugoscNicku;

        int dlugoscReszty = dane.Length - offsetReszty;
        byte[] reszta = new byte[dlugoscReszty];
        Buffer.BlockCopy(dane, offsetReszty, reszta, 0, dlugoscReszty);

        byte[] nowaTablica = new byte[4 + nowyNickBytes.Length + dlugoscReszty];
        Buffer.BlockCopy(nowaDlugoscNicku, 0, nowaTablica, 0, 4);
        Buffer.BlockCopy(nowyNickBytes, 0, nowaTablica, 4, nowyNickBytes.Length);
        Buffer.BlockCopy(reszta, 0, nowaTablica, 4 + nowyNickBytes.Length, dlugoscReszty);

        return nowaTablica;
    }
   
}
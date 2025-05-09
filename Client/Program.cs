using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using SharedLibrary.Models;


public class SocketClient{
    public bool koniec = false;
    private string nick = "";
    private string kluczPrywatny = "";
    private bool powiadomienia = true;
    private bool czyOtrzymanoOdpowiedz = false;
    private bool testPolaczeniaSzyfrowanego = false;
    private string testowyString = "Testowy string weryfikujący poprawność połączenia szyfrowanego klient-serwer";
    private CancellationTokenSource timeOut = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    private Ramka ramka = new Ramka();
    Dictionary<string, byte[]> kluczeSymetryczne = new Dictionary<string, byte[]>(); //nick,kluczSym
    private bool czyZaakceptowanoNick = false;
    private ManualResetEventSlim oczekiwanieNaOdpowiedz = new ManualResetEventSlim(false);
    private int czasOczekiwania = 10;


    public static int Main(String[] args)
        {
            
            SocketClient sc = new SocketClient();
            Task t = new Task(() => sc.StartClient());
            t.Start();
            while (!sc.koniec){
                Task.Delay(100).Wait();
            }
            return 0;
        }

    
    private class Ramka{
        public int kod {set; get;}
        public byte[] dane {set; get;}
    }

    public void OdebranaWiadomosc(int kod, byte[] dane, WatekKlientaTCP wt){
        //Console.WriteLine("================Otrzymano od serwera: "+kod);
        switch(kod){
            case 0:
                if(Encoding.UTF8.GetString(dane).Equals("accepted")){
                    czyZaakceptowanoNick = true;
                }
                else{
                    Console.WriteLine("Serwer nie zaakceptował nicku. Jest on już w użyciu!");
                    koniec = true;
                }
            break;
            case 1:
                ramka.kod = kod;
                ramka.dane = dane;
                czyOtrzymanoOdpowiedz = true;
                oczekiwanieNaOdpowiedz.Set();
            break;
            case 3:
                int dlugoscNicku = BitConverter.ToInt32(dane, 0);
                byte[] bajtyOdbiorcy = new byte[dlugoscNicku];
                Buffer.BlockCopy(dane, 4, bajtyOdbiorcy, 0, dlugoscNicku);
                nick = Encoding.UTF8.GetString(bajtyOdbiorcy);

                int offsetDlugoscDanych = 4 + dlugoscNicku;

                int dlugoscDanych = BitConverter.ToInt32(dane, offsetDlugoscDanych);

                int offsetDanych = offsetDlugoscDanych + 4;

                byte[] zaszyfrowaneDane = new byte[dlugoscDanych];
                Buffer.BlockCopy(dane, offsetDanych, zaszyfrowaneDane, 0, dlugoscDanych);

                byte[] odszyfrowanaWiadomosc = ZaszyfrujOdszyfrujWiadomosc(kluczeSymetryczne[nick], zaszyfrowaneDane, 1);

                Console.WriteLine($"Wiadomość od {nick}: {Encoding.UTF8.GetString(odszyfrowanaWiadomosc)}");
                wt.WyslijWiadomosc(8, bajtyOdbiorcy);

            break;
            case 5:
                if(powiadomienia){
                    var nazwa = Encoding.UTF8.GetString(dane);
                    Console.WriteLine($"Użytkownik {nazwa} chce się z Tobą połączyć.");
                }
            break;
            case 8:
                nick = Encoding.UTF8.GetString(dane);
                Console.WriteLine($"Połączenie z użytkownikiem {nick} zostało utracone.");
                kluczeSymetryczne.Remove(nick);
            break;
            case 9:
                nick = Encoding.UTF8.GetString(dane);
                Console.WriteLine($"Użytkownik {nick} odczytał twoją wiadomość");
            break;
            case 10:
                
                testPolaczeniaSzyfrowanego = true;
            break;
            case 101:
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()){  
                    byte[] odszyfrowanyTekst;
                    int keySizeInBytes = rsa.KeySize / 8;
                    rsa.FromXmlString(kluczPrywatny);  
                    using (MemoryStream ms = new MemoryStream()){
                         for (int i = 0; i < dane.Length; i += keySizeInBytes){
                            int blockSize = Math.Min(keySizeInBytes, dane.Length - i);
                            byte[] block = new byte[blockSize];
                            Buffer.BlockCopy(dane, i, block, 0, blockSize);

                            try{
                            byte[] decryptedBlock = rsa.Decrypt(block, fOAEP: false); // PKCS#1 v1.5
                            ms.Write(decryptedBlock, 0, decryptedBlock.Length);
                            }
                            catch(Exception e){
                                Console.WriteLine(e.ToString());
                            }
                            //Console.WriteLine("PRZYSZLA ODPOWIEDZ");
                            
                         }
                        odszyfrowanyTekst = ms.ToArray();
                    }
                    ramka = new Ramka();
                    ramka.kod = kod;
                    ramka.dane = odszyfrowanyTekst;
                    czyOtrzymanoOdpowiedz = true;
                    oczekiwanieNaOdpowiedz.Set();
                    
                }  
            break;
            case 102:
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()){  
                    byte[] odszyfrowanyTekst;
                    int keySizeInBytes = rsa.KeySize / 8;
                    rsa.FromXmlString(kluczPrywatny);  
                    using (MemoryStream ms = new MemoryStream()){
                         for (int i = 0; i < dane.Length; i += keySizeInBytes){
                            int blockSize = Math.Min(keySizeInBytes, dane.Length - i);
                            byte[] block = new byte[blockSize];
                            Buffer.BlockCopy(dane, i, block, 0, blockSize);

                            try{
                            byte[] decryptedBlock = rsa.Decrypt(block, fOAEP: false); // PKCS#1 v1.5
                            ms.Write(decryptedBlock, 0, decryptedBlock.Length);
                            }
                            catch(Exception e){
                                Console.WriteLine(e.ToString());
                            }
                            //Console.WriteLine("PRZYSZLA ODPOWIEDZ");
                            
                         }
                        odszyfrowanyTekst = ms.ToArray();
                    }
                    ramka = new Ramka();
                    ramka.kod = kod;
                    ramka.dane = odszyfrowanyTekst;
                    czyOtrzymanoOdpowiedz = true;
                    oczekiwanieNaOdpowiedz.Set(); 
                }  
            break;
        }
        
    }

    public void ZakonczPolaczenie(WatekKlientaTCP wt){
        koniec = true;
    }

    public void StartClient(){
        byte[] bytes = new byte[1024];

        try{
            IPHostEntry host = Dns.GetHostEntry("localhost");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);

            Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp); 

            try{
                sender.Connect(remoteEP);
                WatekKlientaTCP wt = new WatekKlientaTCP(sender, OdebranaWiadomosc, ZakonczPolaczenie);
                Task t = new Task(wt.Start);
                t.Start();


                Console.WriteLine("Podaj swój nick");
                nick = Console.ReadLine().Trim();
                wt.WyslijWiadomosc(0, Encoding.UTF8.GetBytes(nick)); //0 - wiadomosc inicjalizujaca (wybor nicku)

                while(!czyZaakceptowanoNick && !koniec){
                    Task.Delay(1000).Wait();
                    if(koniec) return;
                    Console.WriteLine("Oczekiwanie na odpowiedź od serwera (akceptacja nicku)...");
                }
                Console.WriteLine($"Twój nick {nick} został zaakceptowany.");

                Console.WriteLine("Generowanie klucza do komunikacji z serwerem...");
                //klient generuje pare kluczy i wysyła do serwera klucz publiczny
                //tak aby ten zaszyfrował nim wiadokość i przesłał do klienta klucz symetryczny do komunikacji z innym klientem
                var klucze = GeneratePublicAndPrivateKey();
                kluczPrywatny = klucze[1];

                wt.WyslijWiadomosc(4, Encoding.UTF8.GetBytes(klucze[0])); //klucz publiczny dla serwera

                //Test poprawnosci dzialania klucza klient-serwer
                Random random = new Random();
                byte[] randomBytes = new byte[50];
                random.NextBytes(randomBytes);
                bool odpowiedz = WyslijWiadomoscIOczekujNaOdpowiedz(wt, 6, randomBytes); //wygeneruj i wyslij losowe bajty zamienione na string
                if(!odpowiedz){
                    koniec = true;
                    return;
                }

                if(!ramka.dane.SequenceEqual(randomBytes)){
                    Console.WriteLine("Test na poprawność szyfrowania komunikacji serwer-klient nie powiódł się!");
                    koniec = true;
                    return;
                }
                Console.WriteLine("Test na poprawność szyfrowania komunikacji serwer-klient powiódł się!");


                while(!koniec){
                    //Console.WriteLine("Wpisz komende ");
                    //Console.WriteLine("Możliwe opcje: ");
                    //Console.WriteLine("? <nick>");
                    //Console.WriteLine("msg <nick>");
                    //Console.WriteLine("acc <nick>");
                    //Console.WriteLine("notif");

                    while (Console.KeyAvailable)
                    {
                        Console.ReadKey(true);
                    }

                    string msg = Console.ReadLine().Trim();

                    string[] czesci = msg.Split(new[] {' '}, 2); //dzieli na max 2 części

                    string typ = czesci[0];
                    string argument = czesci.Length > 1 ? czesci[1] : "";

                    switch(typ){
                        case "?":
                            ObslozZapytanieOUzytkownika(argument, wt);
                        break;
                        case "msg":
                            WyslijWiadomosc(argument, wt);
                        break;
                        case "acc":
                            ZaakceptujKlienta(argument, wt);
                        break;
                        case "notif":
                            if(powiadomienia){
                                Console.WriteLine("Wyłączono powiadomienia");
                                powiadomienia = false;
                            }
                            else{
                                Console.WriteLine("Włączono powiadomienia");
                                powiadomienia = true;
                            }
                        break;
                        default:
                            Console.WriteLine("Nieznane polecenie!");
                        break;
                    }
                }

                koniec = true;
            }
            catch (ArgumentNullException ane){
                Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
            }
        }
        catch(Exception e){
            Console.WriteLine(e.ToString());
        }
    }

    private static string[] GeneratePublicAndPrivateKey(){
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        string publicKey = rsa.ToXmlString(false);
        string privateKey = rsa.ToXmlString(true);

        return new string[] {publicKey, privateKey};
    }

    private void ObslozZapytanieOUzytkownika(string nickKlienta, WatekKlientaTCP wt){
        if(kluczeSymetryczne.ContainsKey(nickKlienta)){
            Console.WriteLine("Nawiązałeś już połączenie z tym użytkownikiem!");
            return;
        }

        bool odpowiedz = WyslijWiadomoscIOczekujNaOdpowiedz(wt, 1, Encoding.UTF8.GetBytes(nickKlienta)); 
        if(!odpowiedz){
            return;
        }

        if(Encoding.UTF8.GetString(ramka.dane).Equals("false")){
            Console.WriteLine("Nie znaleziono szukanego użytkownika");
            return;
        }

        Console.WriteLine($"Znaleziono użytkownika {nickKlienta}. Czy chcesz się z nim połączyć? (y)");
        string input = Console.ReadLine().Trim().ToLower();

        if(!input.Equals("y")){
            return;
        }



        Console.WriteLine("Nawiązywanie połączenia...");
        odpowiedz = WyslijWiadomoscIOczekujNaOdpowiedz(wt, 2, Encoding.UTF8.GetBytes(nickKlienta)); 
        if(!odpowiedz){
            wt.WyslijWiadomosc(7, Encoding.UTF8.GetBytes(nickKlienta)); //Anulowanie oczekiwania (nickklienta nie będzie mógł użyć już accept wobec nas)   
            return;
        }

        
        // 102 <sym key> - oczekuje na klucz sym
        byte[] kluczSym = ramka.dane;
        kluczeSymetryczne[nickKlienta] = kluczSym;
        Console.WriteLine($"Pomyślnie utworzono połączenie szyfrowane z {nickKlienta}.");


    }

    private bool WyslijWiadomoscIOczekujNaOdpowiedz(WatekKlientaTCP wt, int kod, byte[] msg){
        czyOtrzymanoOdpowiedz = false;
        oczekiwanieNaOdpowiedz.Reset();
        wt.WyslijWiadomosc(kod,msg);

        bool czyOdpowiedzPrzyszla = oczekiwanieNaOdpowiedz.Wait(TimeSpan.FromSeconds(czasOczekiwania));

        if(!czyOdpowiedzPrzyszla){
            Console.WriteLine("Przekroczono czas oczekiwania na odpowiedź serwera!");
            return false;
        }
        return true;
    }

    private void ZaakceptujKlienta(string nickKlienta, WatekKlientaTCP wt){
        bool odpowiedz = WyslijWiadomoscIOczekujNaOdpowiedz(wt, 5, Encoding.UTF8.GetBytes(nickKlienta)); 
        if(!odpowiedz){
            return;
        }

        //albo juz nie oczekuje albo oczekuje i dostajemy klucz sym (102)
        switch(ramka.kod){
            case 102:
                byte[] kluczSym = ramka.dane;
                kluczeSymetryczne[nickKlienta] = kluczSym;
                Console.WriteLine($"Pomyślnie utworzono połączen ie szyfrowane z {nickKlienta}");
            break;
            case 7:
                Console.WriteLine($"{nickKlienta} już nie oczekuje na akceptacje Twojego połąćzenia.");
                return;
        }
        if(Encoding.UTF8.GetString(ramka.dane).Equals("false")){
            Console.WriteLine("Nie znaleziono szukanego użytkownika");
            return;
        }
    }

    private void WyslijWiadomosc(string argument, WatekKlientaTCP wt){
        string[] czesci = argument.Split(new[] {' '}, 2);
        if(czesci.Length != 2){
            Console.WriteLine("Niepoprawna liczba argumentów!");
            return;
        }

        if(!kluczeSymetryczne.ContainsKey(czesci[0])){
            Console.WriteLine($"Nie nawiązano połączenia z użytkownikiem {czesci[0]}. Użyj ? <nick> do nawiązania połączenia.");
            return;
        }

        string odbiorca = czesci[0];
        string wiadomosc = czesci[1];

        byte[] bajtyWiadomosci = Encoding.UTF8.GetBytes(wiadomosc);

        byte[] zaszyfrowanaWiadomosc = ZaszyfrujOdszyfrujWiadomosc(kluczeSymetryczne[odbiorca], bajtyWiadomosci, 0);
        byte[] bajtyOdbiorcy = Encoding.UTF8.GetBytes(odbiorca);
        byte[] dlugoscNicku = BitConverter.GetBytes(bajtyOdbiorcy.Length);
        byte[] dlugoscDanych = BitConverter.GetBytes(zaszyfrowanaWiadomosc.Length);

        byte[] bajtyDoPrzeslania = new byte[4 + bajtyOdbiorcy.Length + 4 + zaszyfrowanaWiadomosc.Length]; //Układ bajtow: dlugoscNicku, nick, dlugoscWIadomosci, wiadomosc
        Buffer.BlockCopy(dlugoscNicku, 0, bajtyDoPrzeslania, 0, 4);
        Buffer.BlockCopy(bajtyOdbiorcy, 0, bajtyDoPrzeslania, 4, bajtyOdbiorcy.Length);
        Buffer.BlockCopy(dlugoscDanych, 0, bajtyDoPrzeslania, 4 + bajtyOdbiorcy.Length, 4);
        Buffer.BlockCopy(zaszyfrowanaWiadomosc, 0, bajtyDoPrzeslania, 4 + bajtyOdbiorcy.Length + 4, zaszyfrowanaWiadomosc.Length);

        wt.WyslijWiadomosc(20,bajtyDoPrzeslania);
    }

    private byte[] ZaszyfrujOdszyfrujWiadomosc(byte[] daneSzyfrujace, byte[] dane, int mode){ //mode = 0 - zaszyfruj, mode = 1 - odszyfruj
        byte[] salt = new byte[8];
        byte[] initVector = new byte[16];
        byte[] haslo = new byte[32];

        Buffer.BlockCopy(daneSzyfrujace, 0, salt, 0, salt.Length);
        Buffer.BlockCopy(daneSzyfrujace, salt.Length, initVector, 0, initVector.Length);
        Buffer.BlockCopy(daneSzyfrujace, salt.Length + initVector.Length, haslo, 0, haslo.Length);

        int iterationsCount = 2000;
        HashAlgorithmName hasher = HashAlgorithmName.SHA256;
        Rfc2898DeriveBytes k1;
        Aes alg = Aes.Create();
        
        MemoryStream stream = new MemoryStream();

        byte[] output;


        switch(mode){
            case 0:
                k1 = new Rfc2898DeriveBytes(haslo, salt, iterationsCount, hasher);
                alg.Key = k1.GetBytes(16);
                alg.IV = initVector;

                output = encryptMessage(stream, alg, k1, dane);
                return output;
            break;
            case 1:

                k1 = new Rfc2898DeriveBytes(haslo, salt, iterationsCount, hasher);
                alg.Key = k1.GetBytes(16);
                alg.IV = initVector;

                try{
                    output = decryptMessage(stream, alg, k1, dane);
                    return output;
                }
                catch(Exception){
                    Console.WriteLine("Podano niepoprawne hasło lub dane zostały uszkodzone!");
                }
            break;

        }
        return new byte[1];
        

    }

    static byte[] encryptMessage(MemoryStream stream, Aes alg, Rfc2898DeriveBytes k1, byte[] data){
        CryptoStream encrypt = new CryptoStream(stream, alg.CreateEncryptor(), CryptoStreamMode.Write);
        encrypt.Write(data, 0, data.Length);
        encrypt.FlushFinalBlock();
        encrypt.Close();
        byte[] edata1 = stream.ToArray();
        k1.Reset();
        return edata1;

    }

    static byte[] decryptMessage(MemoryStream stream, Aes alg, Rfc2898DeriveBytes k1, byte[] data){
        CryptoStream decrypt = new CryptoStream(stream, alg.CreateDecryptor(), CryptoStreamMode.Write);
        decrypt.Write(data, 0, data.Length);
        decrypt.Flush();
        decrypt.Close();
        k1.Reset();
        return stream.ToArray();

    }

}

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

// <typ wiadomosci> <wartosc>

// Wiadomosci od serwera
// 0 accepted/rejected                  -  akceptacja lub odrzucenie propozycji nicku przez klienta
// 1 true/false                         -  odpowiedź czy klient o danym nicku istnieje
// 3 <nick> <msg>                       -  wiadomość od użytkownika
// 2 notFound/accepted/alreadyConnected         -  informacja czy udało się nawiązać szyfrowane połączenie z klientem lub czy już zostało nawiązane
// 5 <nick>                             -  informacja ze dany klient chce sie polaczyc
// 102 <sym key>                          -  klucz do komunikacji po akceptacji klienta
// 7                                    -  klient juz nie oczekuje na akceptacje 
// 8 <nick>                             -  polaczenie z uzytkownikiem <nick> zostalo utracone
// 9 <nick>                             -  potwierdzenie ze uzytkownik odczyutal wiadomosc
// 10 <testowaZaszygrowanaWiadomoscDoKlienta>
// 22 <nick>                            -  serwer podczas obsługi żądania 20 (wysyłanai wiadomości) odkrył, że odbiorca nie istnieje

//Wiadomosci szyfrowane mają typ większy lub równy 100. Ich typ po odszyfrowaniu zmniejsza sie o 100 i dalej są traktowane jako nieszyfrowane


// Wiadomosci do serwera
// 0 <nick>        -  prośba o zaakceptowanie nicku użytkownika przez serwer
// 1 <nick>        -  zapytanie czy użytkownik o danym nicku istnieje
// 2 <nick>        -  nawiązanie połącznia z użytkownikiem o podanym nicku
// 20 <nick> <msg>  -  wysłanie wiadomości do użytkownika
// 4 <klucz publiczny klienta do komunikacji serwer - klient>  -  wysłanie wiadomości do serwera z treścią klucza publicznego utworzonego przez klienta
// 5 <nick>        - akceptacja polaczenia z danym klientem
// 8 <nick>        - wysłanie potwierdzenia odbioru wiadomości od użytkownika

//Komunikacja klienta z serwerem:
// ? <nick> - sprawdzenie czy istnieje dany klient i jeśli istnieje to pyta czy wysłać prośbę o rozpoczęcie połączenia szyfrowanego (y/n)
// msg <nick> - wysłanie wiadomości do danego klienta
// acc <nick> - akceptuje prośbę o połączenie z klientem
// notif      - włącza lub wyłącza powiadomienia o prośbie nawiązania połączenia

namespace SharedLibrary.Models{
 public class WatekKlientaTCP{
        public bool koniec = false;
        public string kluczPubliczny = "";
        public string nazwa = "";
        public HashSet<string> polaczenia = new HashSet<string>();
        public HashSet<string> oczekujacy = new HashSet<string>(); 
        Task? taskOdbierane = null;
        Socket? gniazdoKlienta = null;
        private Action<int, byte[], WatekKlientaTCP> ?OdbieranieWiadomosciCallback = null;
        private Action<WatekKlientaTCP> ?ZakonczPoloczenieCallback = null;
        public string Name{
            get{
                IPEndPoint remoteIpEndPoint = gniazdoKlienta.RemoteEndPoint as IPEndPoint;

                if(remoteIpEndPoint != null){
                    return "" + remoteIpEndPoint.Address + ":" + remoteIpEndPoint.Port;
                }
                else return "";
            }
        }

        public WatekKlientaTCP(Socket gniazdoKlienta, Action<int, byte[], WatekKlientaTCP> OdbieranieWiadomosciCallback = null, Action<WatekKlientaTCP> ZakonczPolaczenieCallback = null){
            this.gniazdoKlienta = gniazdoKlienta;
            this.OdbieranieWiadomosciCallback = OdbieranieWiadomosciCallback;
            this.ZakonczPoloczenieCallback = ZakonczPolaczenieCallback;
        }

        public void ZakonczPolaczenie(){
            Console.WriteLine("[" + this.Name+"]: zakończenie połączenia");
            koniec = true;

            try{
                gniazdoKlienta.Shutdown(SocketShutdown.Both);
                gniazdoKlienta.Close();
                if(ZakonczPoloczenieCallback != null)
                    ZakonczPoloczenieCallback(this);
            }
            catch(Exception e){}
        }

        public bool CzyPolaczony(){
            try{
                return !(gniazdoKlienta.Poll(10000,SelectMode.SelectRead) && gniazdoKlienta.Available == 0);
            }
            catch(SocketException) {return false;}
        }

        public void WyslijWiadomosc(int typ, byte[] dane){
            //Console.WriteLine(this.Name + ": wysyłanie wiadomości: "+typ);

            byte[] mesType = BitConverter.GetBytes(typ);

            if(typ >= 100){ //szyfrowanie
                var zaszyfrowaneDane = ZaszyfrujWIadomosc(kluczPubliczny, dane);
                dane = zaszyfrowaneDane;
            }

            byte[] responseLen = BitConverter.GetBytes(dane.Length);

            gniazdoKlienta.Send(mesType, 0, mesType.Length, SocketFlags.None);
            gniazdoKlienta.Send(responseLen, 0, 4, SocketFlags.None);
            gniazdoKlienta.Send(dane, 0, dane.Length, SocketFlags.None);
        }

        public void WyslijSzyfrowanaWiadomosc(int typ, string msg){
            Console.WriteLine(this.Name + ": wysyłanie wiadomości szyfrowanej: "+msg);
            byte[] dane = Encoding.UTF8.GetBytes(msg);
            byte[] zaszyfrowaneDane;   
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()){
                rsa.FromXmlString(kluczPubliczny);                           //zamieniamy bity na bajty (/8) i odejmujemy 11 bajtów paddingu
                zaszyfrowaneDane = SzyfrujBloki(dane, (rsa.KeySize/8) - 11, rsa);  
            }  

            byte[] mesType = BitConverter.GetBytes(typ);
            byte[] responseBytes = zaszyfrowaneDane;
            
            byte[] responseLen = BitConverter.GetBytes(responseBytes.Length);

            gniazdoKlienta.Send(mesType, 0, mesType.Length, SocketFlags.None);
            gniazdoKlienta.Send(responseLen, 0, 4, SocketFlags.None);
            gniazdoKlienta.Send(responseBytes, 0, responseBytes.Length, SocketFlags.None);
        }

        public void OdbierzWiadomosc(int typ, byte[] wiadomosc, WatekKlientaTCP wt){
            if(OdbieranieWiadomosciCallback != null)
                OdbieranieWiadomosciCallback(typ, wiadomosc, wt);
            else{
                Console.WriteLine("Nie zdefiniowano funkcji odbiuru wiadomosci!");
            }
        }

        public void Start(){
            taskOdbierane = new Task(() => {
                string ?data = null;
                byte[] ?bytes = null;
                Console.WriteLine("[" + this.Name + "]: start wątku odbierającego dane");
                
                while(!koniec){
                    byte[] typeBuffer = new byte[4];
                    OdbierzDane(typeBuffer, 0, 4);
                    int typ = BitConverter.ToInt32(typeBuffer, 0);

                    byte[] lengthBuffer = new byte[4];
                    OdbierzDane(lengthBuffer, 0, 4);
                    int dlugoscDanych = BitConverter.ToInt32(lengthBuffer, 0);


                    // 3. Odbierz właściwe dane
                    byte[] dataBuffer = new byte[dlugoscDanych];
                    OdbierzDane(dataBuffer, 0, dlugoscDanych);

                    OdbierzWiadomosc(typ,dataBuffer,this);
                    
                }
            });

            taskOdbierane.Start();

            Task sprawdzPolaczenie = new Task(() => {
                while(!koniec){
                    if(!CzyPolaczony()){
                        Console.WriteLine("Konczenie w Task sprawdzPolaczenie");
                        ZakonczPolaczenie();
                    }
                    Task.Delay(100).Wait();
                }
            });
            //sprawdzPolaczenie.Start();
        }

        private void OdbierzDane(byte[] buffer, int offset, int size){
            try{
                int receivedTotal = 0;
                while (receivedTotal < size){
                    int received = gniazdoKlienta.Receive(
                    buffer, 
                    offset + receivedTotal, 
                    size - receivedTotal, 
                    SocketFlags.None
                    );
        
                    if (received == 0)
                        throw new SocketException(); // Połączenie zostało zamknięte
            
                    receivedTotal += received;
                }
            }
            catch(Exception){
                ZakonczPoloczenieCallback(this);
            }
        }

        private static byte[] ZaszyfrujWIadomosc(string kluczPubliczny, byte[] daneDoZaszyfrowania){
   
        byte[] zaszyfrowaneDane;   
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())  
        {
            rsa.FromXmlString(kluczPubliczny);                           //zamieniamy bity na bajty (/8) i odejmujemy 11 bajtów paddingu
            zaszyfrowaneDane = SzyfrujBloki(daneDoZaszyfrowania, (rsa.KeySize/8) - 11, rsa);  
        }  
        return zaszyfrowaneDane;
    }


        private static byte[] SzyfrujBloki(byte[] dane, int maxBlockSize, RSACryptoServiceProvider rsa){
        using (MemoryStream ms = new MemoryStream()){
            for (int i = 0; i < dane.Length; i += maxBlockSize){
                int blockSize = Math.Min(maxBlockSize, dane.Length - i);
                byte[] block = new byte[blockSize];
                Buffer.BlockCopy(dane, i, block, 0, blockSize);
                byte[] encryptedBlock = rsa.Encrypt(block, false); //starszy padding (false) PKCS#1
                ms.Write(encryptedBlock, 0, encryptedBlock.Length);
            }
            return ms.ToArray();
        }
    }


    }
}
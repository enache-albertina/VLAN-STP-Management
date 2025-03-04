##  **Am implementat in cod urmatoarele functionalitati:**

    - tabela de comutare
    - vlan
    - stp

## **Implementarea VLAN-urilor**

    Virtual Local Area Networks (VLAN) permit segmentarea logica a retelelor,
separand traficul pentru diferite grupuri de dispozitive.  In aceasta 
implementare, VLAN-urile sunt gestionate pentru a controla ce pachete sunt
transmise pe porturi specifice printr-un identificator de VLAN si ce porturi 
sunt transmise pe cele de tip trunk.
    
 ###   **Tratarea pachetelor pe bază de VLAN:**

Funcțiile multicast_trunk_number și unicast_trunk_number gestionează forwardarea
pachetelor în funcție de VLAN-ul fiecărui port, utilizând informația 
din dicționarul VLAN.

**Funcția multicast_trunk_number:**
    Dacă un pachet vine de pe un port de tip acces și trebuie transmis pe
un port de tip trunk, funcția adaugă un tag VLAN la pachet pentru a
specifica VLAN-ul pachetului.

Dacă pachetul vine de pe un port trunk și trebuie trimis pe un port de acces, 
funcția elimină tag-ul VLAN pentru a permite dispozitivului final să proceseze
cadrul fără complicații.


**Funcția unicast_trunk_number:**
Similar cu multicast_trunk_number, această funcție direcționează pachetele
unicast în funcție de VLAN-ul destinației. Se adaugă sau elimină tag-uri 
VLAN în funcție de tipul portului (trunk sau acces).


## Implementarea Protocolului Spanning Tree (STP)

Scopul principal al protocolului Spanning Tree (STP) este de a preveni
buclele în rețelele Ethernet prin construirea unei topologii logice
fără bucle. În această implementare, fiecare switch începe prin a se considera
„root bridge” (switch-ul rădăcină). Apoi, prin schimbul de informații prin
pachete BPDU, fiecare switch ajunge să convergă către un singur root
bridge și să blocheze căile redundante.

## Principalele componente ale implementării
Inițializarea switch-ului:


## **Stările porturilor:**

În STP, porturile pot avea diferite stări, cum ar fi BLOCKING și LISTENING,
folosite în acest script.
Inițial, toate porturile de tip trunk sunt setate pe BLOCKING, deoarece buclele
pot apărea doar între switch-uri conectate prin porturi de tip trunk.
Dacă un switch este root bridge, acesta desemnează toate porturile sale ca 
LISTENING pentru a permite redirecționarea normală a cadrelor.


## **Structura pachetelor BPDU:**

Bridge Protocol Data Units (BPDUs) sunt pachete speciale utilizate în STP 
pentru a comunica între switch-uri informații despre bridge ID și costul 
drumului către root bridge.
Această implementare structurează pachetele BPDU conform specificațiilor STP:
Adresa MAC de destinație: Setată la 01:80:C2:00:00:00, o adresă multicast
specifică pentru STP.
Header-ul LLC: Folosește valori specifice pentru a identifica protocolul
(DSAP și SSAP sunt setate la 0x42, iar controlul este setat la 0x03).

Header-ul și Configurația BPDU: Conține câmpuri precum root_bridge_ID,
sender_bridge_ID, root_path_cost și alte parametri necesari.


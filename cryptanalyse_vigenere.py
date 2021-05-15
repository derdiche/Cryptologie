# Sorbonne Université 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : NOM ET NUMERO D'ETUDIANT
# Etudiant.e 2 : NOM ET NUMERO D'ETUDIANT

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# Fréquence moyenne des lettres en français
freq_FR = [0.084, 0.0106, 0.0303, 0.0418, 0.1726, 0.0112, 0.0127, 0.0092, 0.0734, 0.0031, 0.0005, 0.0601, 0.0296, 0.0713, 0.0526, 0.0301, 0.0099, 0.0655, 0.0808, 0.0707, 0.0574, 0.0132, 0.0004, 0.0045, 0.0030, 0.0012]

# Chiffrement César
def chiffre_cesar(l, key):
	m=""
	for i in l:
		s=(((ord(i)-ord('A')+key)%25)+ord('A'))
		m+=chr(s)
	return m

# Déchiffrement César
def dechiffre_cesar(l, key):
	m=""
	for i in l:
		s=(((ord(i)-ord('A'))-key) %26)+ord('A')
		m+=chr(s)
	return m


# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
	l=""
	for i in range (len(txt)) :
		l+=chr((((ord(txt[i])-ord('A'))+key[i%len(key)])%26)+ord('A'))
	return l

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
	l=""
	for i in range (len(txt)) :
		l+=chr((((ord(txt[i])-ord('A'))-key[i%len(key)])%26)+ord('A'))
	return l

# Analyse de fréquences
def freq(txt):
	hist=[0.0]*len(alphabet)
	for i in txt:
		hist[ord(i)-ord('A')]+=1
	return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
	tab=freq(txt)
	max = tab[0]
	ind=0
	for i in range (len(tab)):
		if tab[i]>max :
			max=tab[i]
			ind=i
	return ind

# indice de coïncidence
def indice_coincidence(hist):
	tot=0
	som=0
	for i in range (len(hist)):
		som+=hist[i]

	if (som<=1):
		return 0

	for i in range (len(hist)):
		tot+=(hist[i]*(hist[i]-1))/(som*(som-1))
	return tot


# Recherche la longueur de la clé
def longueur_clef(cipher):
	moy=[]
	for j in range (1,21):
		tab=[]
		tab1=[]
		som=0
		for i in range (j):
			tab=cipher[i: :j]
			tab1.append(indice_coincidence(freq(tab)))
		for p in tab1:
			som+=p
		moy.append(som/len(tab1))

	for k in range (len(moy)):
		if moy[k]>0.06:
			return k+1


    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne

def clef_par_decalages(cipher, key_length):
    decalages=[0]*key_length
    for i in range (key_length):
        tab=[]
        for j in range (i, len(cipher), key_length):
            tab.append(cipher[j])
        lettre_max=chr(lettre_freq_max(tab)+ord('A'))
        decal=((ord(lettre_max)-ord('E'))%26)
        decalages[i]+=decal
    return decalages

# Cryptanalyse V1 avec décalages par frequence max

def cryptanalyse_v1(cipher):
    length_key= longueur_clef(cipher)
    decal = clef_par_decalages (cipher, length_key)
    return dechiffre_vigenere(cipher, decal)

#La première forme de cryptanalyse ne fonctionne que sur les textes longs
#car il est difficile de manipuler les fréquences pour trouver la lettre la plus fréquente
#d'une colonne quand il y a peu de lettres.
#En lançant le test 5, nous obtenons 18 textes correctement cryptanalysées.
    
    
################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    h2_1=[0.0]*len(h2)
    tot1=0
    tot2=0
    ICM=0
    for i in h1:
        tot1 = tot1+ i
    for i in h2:
        tot2+=i
    for i in range (len(h2_1)):
        h2_1[(i-d)%26]+=h2[i]
    for i in range (len(h1)):
        ICM+=(h1[i]*h2_1[i])/(tot1*tot2)
    return ICM

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
    
def tableau_decalages_ICM(cipher, key_length):
    decalages=[0]*key_length
    tab1=[]
    for i in range (0, len(cipher), key_length):
        tab1.append(cipher[i])
    for i in range (key_length):
        ind=0
        max=0
        tab=[]
        for j in range (i, len(cipher), key_length):
            tab.append(cipher[j])
        for d in range (len(alphabet)):
            if (indice_coincidence_mutuelle(freq(tab1),freq(tab), d)>max):
                max=indice_coincidence_mutuelle(freq(tab1),freq(tab), d)
                ind=d
        decalages[i]+=ind
    return decalages

# Cryptanalyse V2 avec décalages par ICM
    
def cryptanalyse_v2(cipher):
    key_length=longueur_clef(cipher)
    decal_relatif=tableau_decalages_ICM(cipher,key_length)
    
    tab=""
    for i in range (0, len(cipher)):
        tab = tab + dechiffre_cesar(cipher[i],decal_relatif[i%key_length])
    cle_decal = clef_par_decalages(tab,1)
    return dechiffre_cesar(tab,cle_decal[0])

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
    

def moyenne(l):
	cpt=0
	for i in l :
		cpt=cpt+i
	return cpt/len(l)

def correlation(L1,L2):
    som1=0
    som2=0
    som3=0
    som4=0
    moy1=moyenne(L1)
    moy2=moyenne(L2)
    for i in range (len(L1)):
        som1+=(L1[i]-moy1)*(L2[i]-moy2)
    for i in range (len(L1)):
        som2+= (L1[i]-moy1)**2
    for i in range (len(L2)):
        som3+=(L2[i]-moy2)**2
    som4+=(math.sqrt(som2))*(math.sqrt(som3))
    return som1/som4

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    key=[0]*key_length
    tab1=[0]*key_length
    score = 0.0
    sc_1=0
    for i in range (key_length):
        tab=[]
        max_cor=0
        for j in range (i, len(cipher), key_length):
        	tab.append(cipher[j])
        for d in range (len(alphabet)):
            if (correlation(freq(dechiffre_cesar(tab, d)), freq_FR)>max_cor):
                max_cor=correlation(freq(dechiffre_cesar(tab, d)), freq_FR)
                ind=d
        key[i]+=ind
        tab1[i]+=max_cor
    score=moyenne(tab1)
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    max = 0
    ind =0
    key1=[]
    for i in range (1,20):
        score, key =(clef_correlations(cipher, i))
        if (score >max):
            max = score
            ind =i
            key1=key
    return dechiffre_vigenere(cipher, key1)


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])

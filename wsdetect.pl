=encoding utf8

=head1 NOMBRE
    	WSDetect


=head1 SINOPSIS
	perl WSDetect  [dirtoanalyze] [quarantinedir] [datafile] 
	OPCIONES:
        I<dirtoanalyze> El análisis será en la ruta especificada. Por omisión es el directorio actual.
	I<quarentinedir> Dónde serán almacenados los archivos que se detecten como maliciosos. Por omisión I</tmp/cuarentenaslocas>
	I<datafile> Archivo que contiene el diccionario de palabras comunes en los webshell. Por omisión I<keywords.txt>

=head1 DESCRIPCIÓN
Este script provee funciones para detectar y reportar código que 
puede ser usado, por un atacante que vulneró un servidor, para alojar 
un I<WebShell>. Se analizan los archivos en un directorio determinado 
y cada uno de los archivos son calificados como B<malicioso>, 
B<posiblemente malicioso>, B<limpio, indeterminado>. 
Los criterios para otorgar una calificación son:

=over

=item * B<Hash de WebShell conocido>

Comparamos el hash del archivo que estamos analizando con un conjunto de 
hashes de webShell conocidos. Si empata con alguno, ya no aplicamos más 
métricas y decimos que es malicios.

=item * B<Palabras de diccionario>. 

El archivo I<Keywords.txt> aloja un conjunto de palabras comúnmente 
usadas en los webshells. Esto se determinó analizando webshells y 
tomando en cuenta información de terceros. Si ningún otro es pasado
en las opciones, ese será usado.

=item * B<Ofuscación>

Si el archivo está codificado en B<base64> tiene altas 
probabilidades de ser malicioso.

=item * B<Número de carácteres por palabra>

=item * B<Numero de caracteres por línea>

=back 

Cuando un archivo es calificado como B<malicioso>, se manda 
a cuarentena. Esto quiere decir, copiar el archivo a un directorio 
especificado y cambiar los
permisos del archivo malicioso a 000 en la ruta original.
 
=cut

# Creando nuestro propio espacio de nombres
#package WebShelLocator;
# Paquete que exporta nuestras funciones del
# espacio local al global para que los scripts
# externos puedan hacer uso de nuestras funciones.
#use Exporter;

use strict;
#use warnings;	dont care :D
#listar archivos
use File::Find;
#mtime
use File::stat;
#ruta absoluta
use File::Spec;
#hashsum 
use IO::File;
use Digest::MD5 qw(md5_hex);
#base64
use MIME::Base64;
#copiar archivos
use File::Copy;
#html
use HTML::Template;


#hash para guardar info estadísticas de los archivos
my @files;

#default values
my $dirtoanalyze = ".";
my $datafile = "keywords.txt";
my $quarantinedir = "/tmp/cuarentenaslocas";
my $malwarehashes = "hashes.txt";
my $templatename = "template.tmpl";
my $logfname = "reporte.html";

#Arreglo que contendra las rutas de los archivos maliciosos
my @listarMal = ();

#Arreglo que contendra las rutas de los archivos posiblemente maliciosos
my @posibles;

#obtenemos los parametros del usuario si es que los proporciono
&getParams($dirtoanalyze,$quarantinedir,$datafile);

#llenamos los arreglos, keywords.txt contiene palabras comunes en los webshells
#hashes.txt contiene hashes md5 de webshells comunes
my @keywords = &getData($datafile);
my %hashes = &getDataToHash($malwarehashes);

#file whitelist, ignoramos estos archivos en el analisis
my @whitelist = &whiteList();


#Creamos el dir de cuarentena
&createDir($quarantinedir);

#Examinamos los archivos del directorio pasado y todos los subdir
&listaArchivos($dirtoanalyze);

#Lista de rutas de archivos infectados
&listarMal();


#Obtiene los datos de un archivo y regresa un arreglo sus palabras
sub getData{
	my @data;
	open (FH, "<",$_[0]) or die "Can't open $_[0] for read: $!";
	while (<FH>) {
		push (@data, split(' ',$_));
	}
	close FH or die "Cannot close $_[0]: $!"; 
	return @data;
}

sub getDataToHash{	
	my %shellhash;
	my @array;
	open(FI,"<",$malwarehashes) or die "Can't open hashesfile $!";
	while(<FI>){
        	chomp($_);
        	@array = split ('\\* ',$_);
        	$shellhash{$array[1]}=$array[0];
	}
	return %shellhash;
}

#Lista todos los archivos del directorio y los subdirectorios
#PARAM:
#	Ruta del directorio
sub listaArchivos{
	#funcion de procesado, ruta de inicio
	finddepth(\&procesaArchivo,$_[0]);
}

#Procesa el archivo pasado
sub procesaArchivo { 
	print "\n\nArchivo: $_";
	if(-d){
		return;
	}
	#Obtenemos info
	&fileStat($_);
};

sub getHash{
	my $hash = md5_hex(do { local $/; IO::File->new($_[0])->getline });
	return $hash;
}

sub analyze{
	#Si esta en la whitelist lo ignoramos
	if (&contains($_[0],\@whitelist)) {
		return;
	}
	my $res = &isMalware($_[0]); 
	if($res==1){
		&cuarentena($_[0]);
		return $res;
	}
	#new
	else{
		return $res;
	}
}

=head1 SUBRUTINAS

=over 

=item * B<isMalware>(I<file>)  
Recibe un único parámetro. I<file> es el archivo a ser analizado. 
Este procedimiento corre todas las metricas, las promedia y obtiene 
una calificación para el archivo.
En caso de ser detectado como malware lo pone en cuarentena.

=cut
    
sub isMalware{
	my $m1;
	my $m2;
	my $m3;
	my $m4;
	my $promedio;
	my $hash = &getHash($_[0]);
	if(defined $hashes{$hash}){
		push @listarMal,$_[0];
		return 1;		
	}
	$m1 = &searchInFile($_[0],\@keywords); 
	$m2 = &ofuscadoB64($_[0]);
	$m3 = &charsWord($_[0]);
	$m4 = &charXLineAVG($_[0]);
	$promedio = ( split(/\./, (($m1 + $m2 + $m3 + $m4)/4)) )[0];
	if($promedio == 1)
	{
		push @listarMal,$_[0];
		return 1;
	}
	if($promedio == 2){
		push @posibles,$_[0];
	}
	return $promedio;
}

=item * B<fileStat>(I<file>)  
Regresa las estadisticas del archivo parametro. Puede ser
en formato html o en la terminal.

=back

=cut
sub fileStat{    
    my $stat_obj = stat $_;
    my $rutaabs = File::Spec->rel2abs($_);
    my $permisos = sprintf "%o",$stat_obj->mode&07777;
    my $uid = $stat_obj->uid;
    my $tam = $stat_obj->size;
    my $inodo = scalar localtime($stat_obj->ctime);
    my $modificado = scalar localtime($stat_obj->mtime);
    my $ultimoacceso = scalar localtime($stat_obj->atime);
    my $hash = &getHash($rutaabs);
    print "\nRuta: $rutaabs";
    print "\nPropietario(uid): $uid";
    print "\nPermisos: $permisos";
    print "\nTamanio(bytes): $tam";
    print "\nCambio Inodo: $inodo";
    print "\nModificado: $modificado";
    print "\nUltimo Acceso: $ultimoacceso";
    print "\nHash(md5): $hash";
    my $resultado = &getCalificacion(&analyze($rutaabs));
    print "\nCalificación: $resultado";

    my %file;    
    $file{"ruta"} = $rutaabs;
    $file{"propietario"} = $uid;
    $file{"permisos"} = $permisos;
    $file{"tamanio"} = $tam;
    $file{"cInodo"} = $inodo;
    $file{"modificado"} = $modificado;
    $file{"ultimo"} = $ultimoacceso;
    $file{"hash"} = $hash;
    $file{"calificacion"} = $resultado;    
    push(@files, \%file);

}

#Métrica del diccionario.
# 1, (>=) 25% 
# 2, (<) 25% (>=) 10%
# 3, (<) 10% (>= ) 5%
# 4, (<) 5%
# Porcentajes calulados en base al total de palabras y número de palabras 
# del diccionario en el archivo 
#Params:
#	Archivo a analizar
#	Referencia a arreglo de palabras que buscar
#	Buscara si la linea contiene alguna palabra en el arreglo
sub searchInFile{
	open (FH,"<",$_[0]) or die "Can't open $_[0] for read: $!";
	my @regexp = @{$_[1]};
	my @encontradas;
	my $cuenta = 0;
        # palabras totales. Una palabra se define algo que está separado por ;, (,),{,},[,],",",  y ,
        my $totales = 0;        
	while (my $line= <FH>) {
		chomp($line);
		foreach (@regexp){
			if ($line=~ /$_/) {
				push @encontradas,$_;
				$cuenta++;
  			}
		}
                $totales += scalar(split(/[\;=\s{}()"'<>\+\*\-\/\$@%]+/,$line));
	}
	close FH or die "Cannot close $_[0]: $!";
	print "\nEl numero de palabras encontradas es $cuenta"; 	
	print "\nPalabras: ",join ",",@encontradas;
	if($cuenta > 0){
            my $ratio = $totales/$cuenta;
            if($ratio >= 0.25){  return 1; }
            if($ratio >= 0.1 ){  return 2; }
            if($ratio >= 0.05 ){  return 3; }
            return 4;
        }
}

#Recibe unicamente el archivo a analizar
sub ofuscadoB64{
        my $lineas=0; #Cuenta las lineas totalesdel archivo
        my $lineasB64=0; #Cuenta las lineas que estan en base 64
        open (FH,"<",$_[0]) or die "Can't open $_[0] for read: $!";
        while (my $line= <FH>) {
                chomp($line);
		if($line=~/
			(  ([A-Za-z0-9\+\/]{4}) | ([A-Za-z0-9\+\/]{2}==)| ([A-Za-z0-9\+\/]{3}=) ){5,}
		/x){
				$lineasB64++;
			}
			$lineas++;
        	}
        close FH or die "Cannot close $_[0]: $!";
        print "\nLineas totales: $lineas\nLineas ofuscadas: $lineasB64";
        if($lineasB64 == 0){return 3;} #esta limpio
        elsif($lineasB64/$lineas >= .8){return 1;} #Si la relacion entre lineas en base64 y lineas totales es mayor al 80%, es malicioso
        elsif($lineasB64/$lineas >= .4){return 2;}#Si es mayor al 40% y menor al 80% es posiblemente malicioso
        return 4;#indefinido
}

#Métrica que que analiza cuántos caracteres hay por línea
sub charXLineAVG{
    open (FH,"<",$_[0]) or die "Can't open $_[0] for read: $!";
    my $param = 80;
    my $lineaXG = 0;
    my $lineas = 0;
    while (my $line= <FH>) {
        chomp($line);
        if(scalar($line) > $param) {$lineaXG++;}
        $lineas++;
    }
    if($lineaXG == 0){return 3;}
    elsif($lineaXG/$lineas >= .8){return 1;} #Si la relacion entre lineas en base64 y lineas totales es mayor al 80%, es malicioso
    elsif($lineaXG/$lineas >= .4){return 2;}#Si es mayor al 40% y menor al 80% es posiblemente malicioso
    return 4;#indefinido
}

#Pensado para codigos del estilo:
# $qwewqchgtnbhmjhdfvgh = $asqwerdftyghbnghkolpm * $mnjhmnlkoivbghtyuhjm;
sub charsWord{
        my $greater20 = 0; #Contador de palabras con mas de 20 caracteres
        open(FH,"<",$_[0]);
        while (my $line=<FH>){
                chomp($line);#Lee cada linea
                my @lineas = split /[\;=\s{}()"'<>\+\*\-\/\$@%]+/,$line;#Separa en palabras la linea usando esos caracteres
                for (@lineas){
                        #print $_,"\t",length $_,"\n";
                        if(length $_ > 20){#Si alguna palabra tiene mas de 20 caracteres, puede estar ofuscado
                                $greater20++;   #Aumenta el contador
                        }
                }
        }
        close FH;
        if($greater20 > 8){return 1;}#Si tiene mas de 8 palabras, es malicioso
        if($greater20 > 4){return 2;}#Si tiene mas de 4 y menos de 8 palabras así, puede ser ofuscado
        return 3;#esta limpio
}


sub cuarentena{
	&backupFile($_[0]);
	&changePermissions($_[0]);
}

sub changePermissions{
	chmod(0000,$_[0]);
}

sub backupFile{
	copy $_[0], $quarantinedir;
}

sub createDir{
	if($_[0]== 0){
		mkdir $_[0];
	}
}

#Agregamos archivos a ignorar: el script, keywords, etc
sub whiteList{
	my @whitelist;
	#Agregamos el script,sino es mandado a cuarentena :v
	push @whitelist,$0;
	push @whitelist,$datafile;
	push @whitelist,$malwarehashes;
	push @whitelist,$templatename;
	push @whitelist,$logfname;
	return @whitelist;
}

# Recibe tres parámetros:
# $dirtoanalyze $quarantinedir $datafile
# Todos son opcionales.
sub getParams{
    if(length $ARGV[0] > 0){
        $_[0] = $ARGV[0];
    }
    if(length $ARGV[1] > 0){
        $_[1] = $ARGV[1];
    }
    if(length $ARGV[2] > 0){
               $_[2] = $ARGV[2];
    }
}

#
#
sub contains{
	for(@{$_[1]}){
		#:/
		if($_[0]=~/$_/){
			return 1;
		}
	}
	return 0;
}

sub listarMal{ 
	my $format = "-"x70;
	print "\n\nArchivos maliciosos\n$format\n";
	print join "\n" , @listarMal;
	print "\n$format\n\nPosibles archivos maliciosos\n$format\n";
	print join "\n",@posibles,"$format\n";
	#####
	open RFILE,">",$logfname or die "Error cant create $logfname";
    	my $template = HTML::Template->new(filename => $templatename);
   	$template->param(filelist => \@files);
    	my $output.=$template->output();
	print "\nEl reporte completo en versión html se encuentra en $logfname \n\n";
	#Esto escribe el html en el archivo
	print RFILE $output;
	
}

sub help{
	print "\nperl $0 <rutaanalisis> <rutacuarentena> <keywordfile>";
	print "\n\t<rutaanalisis> El analisis será en la ruta especificada. Por omisión es el directorio actual";
	print "\n\t<rutacuarentena> Dónde serán almacenados los archivos que se detecten como maliciosos. Por omisión $quarantinedir";
	print "\n\t<keywordfile> Archivo que contiene el diccionario de palabras comunes en los webshell. Por omisión $datafile \n";
}

sub getCalificacion{
			 #En whitelist
	my @calificaciones = ("Limpio","Malicioso","Posiblemente Malicioso","Limpio","Indeterminado");
	return $calificaciones[$_[0]];
}

=head1 LICENCIA

				WTFPL LICENSE
	
	Everyone is permited to copy and distribute verbatim or modified
	copies of this license document, and changing it is allowed as long
			    as the name is changed.

		  DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
	TERMS AND CONDITIONS FOR COPYING,DISTRIBUTION AND MODIFICATION
		0. You just DO WHAT THE FUCK YOU WANT TO

			       	   HAVE FUN

		          (⌐■_■)(⌐■_■)(⌐■_■)(⌐■_■)

=head1 AUTORES

=over

=item Diana Arrienta

=item Gonzalo 

=item Virgilio

=item Diana Montes	  

=item Jośe López

=back

=cut

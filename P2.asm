ImprimirCadena MACRO caden
	INVOKE StdOut, ADDR caden
ENDM

Calcular MACRO numero
	MOV AL, numero
	ADD AL, 30H
	MOV numero, AL
ENDM

MAPEO MACRO I, J ;I = NUMERO FILA BUSCAR, J = COLUMNA A BUSCAR
    XOR EAX, EAX
    MOV AX, I
    MOV BL, 1Ah
    MUL BL
    ADD AX, J
ENDM

MapeoM MACRO Ind, Jind, Col, Tam
	MOV AL, Ind
	MOV BL, Col
	MUL BL
	MOV BL, Tam
	MUL BL
	MOV CL, AL
	MOV AL, Jind
	MOV BL, Tam
	MUL BL
	ADD AL, CL
ENDM

.386
.MODEL flat, stdcall
OPTION casemap:none			;convencion sobre mayusculas o minusculas al pasar parametros
INCLUDE		\masm32\include\windows.inc				;.INC
INCLUDE     \masm32\include\kernel32.inc
INCLUDE		\masm32\include\masm32.inc
INCLUDE		\masm32\include\masm32rt.inc
;INCLUDELIB					;.LIB
.DATA
	
	str1 db "Menu ",10,13,0
	str2 DB "1. Generar criptograma ",10,13,0
	str3 db "2. Generar criptograma con variante ",10,13,0
	str4 db "3. Descifrar criptograma ",10,13,0
	str5 db "4. Estadistica de letras ",10,13,0
	str8 db "5. Finalizar",13,10,0
	str6 db "Ingresar cadena ",13,10,0
	str7 db "Ingresar clave ",13,10,0
	str20 db "Opcion no valida ",10,13,0
	str21 DB "Descifrado normal",10, 13, 0
	str22 DB 13,10, "Descifrado con variante",10,13,0
	opcion db 4 dup(0),0
	Mensaje dw 800 dup(0),0
	Clave DW 800 dup(0),0
	MensajeMod DW 800 dup ("$"),0
	ClaveMod DW 800 dup ("$"),0
	CaracteresM DB 100 dup(0),0 ;CANTIDAD CARACTERES EN MENSAJE
	CaracteresC DB 100 dup(0),0 ;CANTIDAD CARACTERES EN LA CLAVE
	prob db 12 dup(0),0
	
	Matriz DB 300 DUP("$"),0 
	str11 DB "Ingrese un mensaje",13,10,0
	str12 DB "Mensaje",13,10,0
	Probabilidad DB "EAOSNRILDUTCMPQYBHVGJFZKWX$",0
	BECEDARIO DB "ABCDEFGHIJKLMNOPQRSTUVWXYZ",0
	Entrada DB 600 DUP("$"),0
	Fila DB 4 DUP(0),0
	Columna DB 4 DUP(0),0
	ABECEDAR DB 4 DUP(0),0
	AUX DB 4 DUP(0),0
	IndiceColumna db 4 DUP(0),0
	Posicion DB 4 DUP(0),0
	CONTADOR DB 4 DUP(0),0
	SALD DB 4 DUP(0),0
	SimboloActual DB 4 DUP(0),0
	ContarEntrada DB 5 DUP(0),0

	MATRIZC DB 676 DUP(0)
	LETRAINI DB 41H
	LETRAFIN DB 5BH
	INDEXC DB 0H
	CARACTER DB 0, 0
	CLAVE2 DB 800 DUP(0), 0

.DATA?
	TMP DD ?
	TMP2 DD ?
	TMP3 DB ?
	TMP4 DB ?
	TMP_C DW ?
	TMP_F DW ?
	TEMP DB ?
	ESI2 DW ?
.CODE
	programa:
	
	CALL LLENARM
	CALL LIMPIAR

	INVOKE StdOut, ADDR str1
	INVOKE StdOut, ADDR str2
	INVOKE StdOut, ADDR str3
	INVOKE StdOut, ADDR str4
	INVOKE StdOut, ADDR str5
	INVOKE StdOut, ADDR str8

	INVOKE StdIn, ADDR opcion,3
	
	MOV AL, opcion
	SUB AL, 30H
	MOV opcion, AL
	CMP AL, 1	
	JE IngresarCriptograma
	CMP AL, 2
	JE IngresarCriptograma
	CMP AL, 3
	JE IngresarDes
	CMP AL, 4
	JE IngresarProb
	CMP AL, 5
	JE finalizar
	INVOKE StdOut, ADDR str20
	jmp programa
	IngresarCriptograma:
		ImprimirCadena str7
		INVOKE StdIn, ADDR ClaveMod, 800
		ImprimirCadena str6
		INVOKE StdIn, ADDR MensajeMod, 800

		CALL LimpiarMensaje
		CALL LimpiarClave
		CALL ContarCadena
		CALL ContarCla
		;MOV Ah,CaracteresM
		;CMP AH, CaracteresC
		;JL Error
		MOV AL, opcion
		CMP AL, 1
		JE CriptogramaNormal
		CMP AL, 2
		JE CriptogramaVariacion
			Error:
				print chr$("La clave es mas grande que el mensaje"),13,10
				jmp finalizar
			CriptogramaNormal:
				;INICIA CIFRADO NORMAL
				print chr$(13, 10)
				CALL CIFRAR
				jmp finalizar
			CriptogramaVariacion:
				print chr$(13, 10)
				CALL CIFRAR2
				jmp finalizar
		jmp finalizar

	IngresarDes:
		ImprimirCadena str7
		INVOKE StdIn, ADDR ClaveMod, 800
		ImprimirCadena str6
		INVOKE StdIn, ADDR MensajeMod, 800

		CALL LimpiarMensaje
		CALL LimpiarClave
		CALL ContarCadena
		CALL ContarCla
		;MOV AL,CaracteresM
		;CMP AH, CaracteresC
		;JL Error2
		JMP CONTINUAR
		Error2:
			print chr$("La clave es mas grande que el mensaje"),13,10
			jmp finalizar
		CONTINUAR:
			;INICIA DESCIFRADO
			print chr$(13, 10)
			INVOKE StdOut, ADDR str21
			CALL DESCIFRAR
			INVOKE StdOut, ADDR str22
			CALL DESCIFRAR2
		jmp finalizar
	IngresarProb:
		MOV Fila, 4d
		MOV Columna,26d
		MOV ABECEDAR, 65d
		INVOKE StdOut, ADDR str11
		INVOKE StdIn, addr Entrada,400d
		CALL Abecedario
		CALL LeerMensaje
		CALL ImprimirMatriz
		print chr$(13,10)
		CALL MostrarProbabilidad
		print chr$(13,10)
		print chr$(13,10)
		CALL CalculoLetras
		INVOKE StdOut, ADDR BECEDARIO
		print chr$(13,10)
		CALL ImprimirMatriz
		print chr$(13,10)
		print chr$(13,10)
		invoke StdOut, ADDR str12
		CALL RomperCifrado

	JMP finalizar

	finalizar:
	print chr$(13, 10)
	INVOKE ExitProcess,0
;---------------------------- Procedimientos-------------------------
	LimpiarMensaje PROC near
		LEA ESI, MensajeMod
		LEA EDI, Mensaje
		IniciarMod:
			MOV AL, 24h
			CMP AL, [ESI]
			JE finLimpiar
			MOV AL, [ESI]
			VerMayuscula:
				CMP AL, "A"
				JAE VerMayusculaMen
				JMP Incrementar
			VerMayusculaMen:
				CMP AL, "Z"
				JBE Agregar
				JMP VerMinuscula
			VerMinuscula:
				CMP AL, "a"
				JAE VerMinusculaMen
				JMP Incrementar
			VerMinusculaMen:
				CMP AL, "z"
				JBE CambiarMinuscula
				jmp Incrementar
		CambiarMinuscula:
		SUB AL, 32d
		jmp Agregar
		Agregar:
			MOV [EDI], AL
			INC EDI
			JMP Incrementar
		Incrementar:
		INC ESI
		JMP IniciarMod
		finLimpiar:
	RET
	LimpiarMensaje ENDP

	LimpiarClave PROC near
		LEA ESI, ClaveMod
		LEA EDI, Clave
		IniciarModCla:
			MOV AL, 24h
			CMP AL, [ESI]
			JE finLimpiarCla
			MOV AL, [ESI]
			VerMayusculaCla:
				CMP AL, "A"
				JAE VerMayusculaMenCla
				JMP IncrementarCla
			VerMayusculaMenCla:
				CMP AL, "Z"
				JBE AgregarCla
				JMP VerMinusculaCla
			VerMinusculaCla:
				CMP AL, "a"
				JAE VerMinusculaMenCla
				JMP IncrementarCla
			VerMinusculaMenCla:
				CMP AL, "z"
				JBE CambiarMinus
				jmp IncrementarCla
		CambiarMinus:
		SUB AL, 32d
		jmp AgregarCla
		AgregarCla:
			MOV [EDI], AL
			INC EDI
			JMP IncrementarCla
		IncrementarCla:
		INC ESI
		JMP IniciarModCla
		finLimpiarCla:
	RET
	LimpiarClave ENDP

	ContarCadena PROC near
	XOR CL, CL
	MOV CaracteresM,0h
	LEA ESI, Mensaje
	MOV CL,0h
	INICIO:
		MOV AL, 24h
		CMP AL, [ESI]
		JE ContarClave
		MOV AL, [ESI]
		CMP AL, 20H
		JE  punto
		CMP AL, 0H
		JE punto
		INC CL
		punto:
		INC ESI
		JMP INICIO
	ContarClave:
		MOV CaracteresM, CL
	RET
	ContarCadena ENDP

	ContarCla proc near
	MOV CaracteresC,0h
	XOR CL, CL
	LEA EDI, Clave
	MOV CL, 0h
	InicioClave:
		MOV AL, 24h
		CMP AL, [EDI]
		JE FinContar
		MOV AL, [EDI]
		CMP AL, 20H
		JE  puntoMedio
		CMP AL, 0H
		JE puntoMedio
		INC CL
	puntoMedio:
		INC EDI
		JMP InicioClave
	FinContar:
		MOV CaracteresC, CL
	ret
	ContarCla ENDP

	LLENARM PROC NEAR ;LLENA LA MATRIZ 
		
		LEA ESI, MATRIZC
		MOV AL, LETRAINI
		
		FOR_J:
			FOR_I:
				MOV [ESI], AL
				;MOV AL, [ESI]
				;MOV AUX, AL
				INC ESI
				INC AL

				CMP LETRAFIN, 5BH
				JZ COMPARARZ
				JMP SALTARZ
				COMPARARZ:
					CMP AL, LETRAFIN
					JNE FOR_I
					CMP AL, LETRAFIN
					JE RESTARZ
					RESTARZ:
						SUB LETRAFIN, 25D ;LETRA FIN ES AHORA UNA A
						JMP FOR_JC
				SALTARZ:
					CMP AL, 5BH
					JZ REINICIARAL
					CMP AL, 5BH
					JNE CONTINUARAL
					REINICIARAL:
						MOV AL, 41H
						JMP FOR_I
					CONTINUARAL:
						CMP AL, LETRAFIN
						JNE FOR_I
						CMP AL, LETRAFIN
						JE SUMARFIN
						SUMARFIN:
							INC LETRAFIN
					
		FOR_JC:
		CMP LETRAINI, 5AH
		JZ ENDFOR
		
		INC LETRAINI
		MOV AL, LETRAINI
		JMP FOR_J
			
		ENDFOR:	
	RET
	LLENARM ENDP

	LIMPIAR PROC NEAR ;LIMPIA LOS REGISTROS EAX, EBX, ECX, EDX
		XOR EAX, EAX
		XOR EBX, EBX
		XOR ECX, ECX
		XOR EDX, EDX
	RET
	LIMPIAR ENDP

	CIFRAR PROC NEAR
		LEA ESI, Mensaje
		LEA EDI, Clave
		
		FOR_J:
			MOV AL, [ESI] ;MENSAJE[ESI]
			MOV BL, [EDI] ;CLAVE[EDI]
			MOV TMP_C, AX ;MENSAJE
			MOV TMP_F, BX ;CLAVE
			MOV TMP, ESI 
			CALL INTERSECCION
			MOV CARACTER, AL
			INVOKE StdOut, ADDR CARACTER
			CALL LIMPIAR
			MOV ESI, TMP
			INC ESI
			INC EDI

			MOV AL, [ESI]
			MOV BL, [EDI]
			CMP AL, 0H
			JZ END_CIFRAR

			CMP BL, 0H
			JZ REPETIR_CLAVE
			JMP FOR_J

			REPETIR_CLAVE:
				LEA EDI, Clave
				JMP FOR_J
			END_CIFRAR:
	RET
	CIFRAR ENDP

	CIFRAR2 PROC NEAR
		LEA ESI, Mensaje
		LEA EDI, Clave
		
		FOR_J2:
			MOV AL, [ESI] ;MENSAJE[ESI]
			MOV BL, [EDI] ;CLAVE[EDI]
			MOV TMP_C, AX ;MENSAJE
			MOV TMP_F, BX ;CLAVE
			MOV TMP, ESI 
			CALL INTERSECCION
			MOV CARACTER, AL
			INVOKE StdOut, ADDR CARACTER
			CALL LIMPIAR
			MOV ESI, TMP
			INC ESI
			INC EDI

			MOV AL, [ESI]
			MOV BL, [EDI]
			CMP AL, 0H
			JZ END_CIFRAR2

			CMP BL, 0H
			JZ REPETIR_CLAVE2
			JMP FOR_J2

			REPETIR_CLAVE2:
				LEA EDI, Mensaje
				JMP FOR_J2
			END_CIFRAR2:
	RET
	CIFRAR2 ENDP

	INTERSECCION PROC NEAR
		;CALCULO DE I
		MOV AX, TMP_C
		SUB AX, 41H
		MOV TMP_C, AX

		;CALCULO DE J
		MOV AX, TMP_F
		SUB AX, 41H
		MOV TMP_F, AX
		
		LEA ESI, MATRIZC
		MAPEO TMP_F, TMP_C
		ADD ESI, EAX
		CALL LIMPIAR
		MOV AL, [ESI]
	RET
	INTERSECCION ENDP

	DESCIFRAR PROC NEAR
		LEA ESI, Mensaje
		LEA EDI, Clave

		FOR_J3:
			CALL LIMPIAR
			MOV AL, [EDI] ;EDI - CLAVE
			MOV BL, [ESI] ;ESI - MENSAJE
			MOV TMP3, BL
			MOV TMP, EDI ; CLAVE
			MOV TMP2, ESI ; MENSAJE
			;TMP_C = I	TMP_F = J
			MOV TMP_C, 0H
			SUB AX, 41H
			MOV TMP_F, AX		

			LEA ESI, MATRIZC
			MAPEO TMP_F, TMP_C ;EAX = POSICIÓN CON LA LETRA DE CLAVE
			ADD ESI, EAX

			MOV TEMP, 0H
			FOR_I:
				CALL LIMPIAR
				MOV BL, TMP3
				CMP [ESI], BL
				JZ END_FORI	

				INC ESI
				INC TEMP
				JMP FOR_I

				END_FORI:
			;CUANDO SALE DEL FOR_I YA SE TIENE EN 
			;TEMP EL VALOR DE COLUMNA
			CALL LIMPIAR
			LEA ESI, MATRIZC
			MOV AL, TEMP
			MOV TMP_C, AX
			MOV TMP_F, 0H
			MAPEO TMP_F, TMP_C
			ADD ESI, EAX
			MOV BL, [ESI]
			MOV CARACTER, BL
			INVOKE StdOut, ADDR CARACTER

			MOV EDI, TMP ;CLAVE
			MOV ESI, TMP2 ;MENSAJE
			INC EDI
			INC ESI

			MOV DL, 0H
			CMP [ESI], DL
			JZ END_FORJ3

			CMP [EDI], DL
			JZ REPETIR_CLAVE

			JMP FOR_J3

			REPETIR_CLAVE:
				LEA EDI, Clave
				JMP FOR_J3

			END_FORJ3:
				
	RET
	DESCIFRAR ENDP

	DESCIFRAR2 PROC NEAR
		LEA ESI, Mensaje
		LEA EDI, Clave
		MOV TMP4, 0H

		FOR_J4:
			CALL LIMPIAR
			MOV AL, [EDI] ;EDI - CLAVE
			MOV BL, [ESI] ;ESI - MENSAJE
			MOV TMP3, BL
			MOV TMP, EDI ; CLAVE
			MOV TMP2, ESI ; MENSAJE
			;TMP_C = I	TMP_F = J
			MOV TMP_C, 0H
			SUB AX, 41H
			MOV TMP_F, AX		

			LEA ESI, MATRIZC
			MAPEO TMP_F, TMP_C ;EAX = POSICIÓN CON LA LETRA DE CLAVE
			ADD ESI, EAX

			MOV TEMP, 0H
			FOR_I2:
				CALL LIMPIAR
				MOV BL, TMP3
				CMP [ESI], BL
				JZ END_FORI2

				INC ESI
				INC TEMP
				JMP FOR_I2

				END_FORI2:
			;CUANDO SALE DEL FOR_I YA SE TIENE EN 
			;TEMP EL VALOR DE COLUMNA
			CALL LIMPIAR
			LEA ESI, MATRIZC
			MOV AL, TEMP
			MOV TMP_C, AX
			MOV TMP_F, 0H
			MAPEO TMP_F, TMP_C
			ADD ESI, EAX
			MOV BL, [ESI]
			MOV CARACTER, BL
			INVOKE StdOut, ADDR CARACTER

			CALL LLENARCLAVE ;LE METE A CLAVE2 EL CARACTER IMPRESO

			MOV EDI, TMP ;CLAVE
			MOV ESI, TMP2 ;MENSAJE
			INC EDI
			INC ESI

			MOV DL, 0H
			CMP [ESI], DL
			JZ END_FORJ4

			CMP [EDI], DL
			JZ REPETIR_CLAVE2

			JMP FOR_J4

			REPETIR_CLAVE2:
				;ACA SE MODIFICA EL LEER CLAVE2
				LEA EDI, CLAVE2
				JMP FOR_J4
			END_FORJ4:		
	RET
	DESCIFRAR2 ENDP

	LLENARCLAVE PROC NEAR
		LEA EDI, CLAVE2
		FOR_V:
			MOV DL, [EDI]
			CMP DL, 0H
			JZ METERCARACTER
			INC EDI
			JMP FOR_V
				
			METERCARACTER:
				MOV DL, CARACTER
				MOV [EDI], DL
	RET
	LLENARCLAVE ENDP
;------------------------ProcedimientosParte4-----------------

Abecedario proc near
	LEA ESI, Matriz
		llenar:
		MOV AL, ABECEDAR
		CMP AL, 91d
		JE FinAbecedario
		MOV [ESI], AL
		MOV AUX, AL
		;INVOKE StdOut, ADDR AUX
		INC ESI
		INC ABECEDAR
		jmp llenar
	FinAbecedario:
	print chr$(13,10)
	;DEC ESI
	MOV bL, 0d
	RellenarCero:
		MOV AL, 1d
		MOV [ESI],AL 
		CMP BL, 26d
		JE FinProc
		MOV AL, "0"
		MOV AUX, AL
		;INVOKE StdOut, ADDR AUX
		INC BL
		INC ESI
		JMP RellenarCero
	FinProc:
RET
Abecedario ENDP 
LeerMensaje PROC near
LEA ESI, Entrada
MOV AL, 0
MOV ContarEntrada, 0d
InicioLeerProb:
MOV AL, [ESI]
CMP AL,24h
JE finLeerCifr

	VerMayuscula:
				CMP AL, "A"
				JAE VerMayusculaMen
				JMP Incrementar
			VerMayusculaMen:
				CMP AL, "Z"
				JBE restarMayuscula
				JMP VerMinuscula
			VerMinuscula:
				CMP AL, "a"
				JAE VerMinusculaMen
				JMP Incrementar
			VerMinusculaMen:
				CMP AL, "z"
				JBE restar
				jmp Incrementar
	restar:
	SUB AL, 97d
	jmp IncrementarCont
	restarMayuscula:
	SUB AL, 65d
	jmp IncrementarCont
	IncrementarCont:
	;ADD AL, 26d
	MOV IndiceColumna, AL
	MapeoM 1d,IndiceColumna,26d,1d
	LEA EDI, Matriz
	MOV BL, AL
	XOR EAX, EAX
	MOV AL, BL
	ADD EDI, EAX
	MOV BL, [EDI]
	INC BL
	MOV [EDI], BL
	INC ContarEntrada
	Incrementar:
	INC ESI
	jmp InicioLeerProb
	finLeerCifr:
RET
LeerMensaje ENDP
ImprimirMatriz PROC near
LEA EDI, Matriz
MOV CONTADOR, 0d
MOV BL, 0d
	InImp:
		mov al, [EDI]
		;ADD AL, 30H
		MOV SALD, AL
		INVOKE StdOut, ADDR SALD
		CMP BL, 25d
		JE salto
		INC BL
		INC EDI
		JMP InImp
	salto:
	print chr$(13,10)
	INC EDI
	MOV BL, 0d
	SaltoDos:
		mov al, [EDI]
		ADD AL, 30H
		MOV SALD, AL
		INVOKE StdOut, ADDR SALD
		CMP BL, 25d
		JE finLinea
		INC BL
		INC EDI
		
	JMP SaltoDos
	finLinea:
RET
ImprimirMatriz ENDP
CalculoLetras PROC near
LEA ESI, Probabilidad
InicioCalculo:
LEA EDI, Matriz
MOV AL, 26d
MOV AUX, 0d
ADD EDI, EAX
	Asignacion:
	MOV AL, AUX
	CMP AL, 26d
	JE FinCalculo
	INC AUX
	MOV AL, [EDI]
	INC EDI
	CMP AL, 0d
	JE Asignacion
	JMP IniciarComparacion
	IniciarComparacion:
	MOV SimboloActual, AL
	MOV BL, AUX
	MOV Posicion, BL
	MOV AUX, 0d
	LEA EDI, Matriz
	MOV AL, 26d
	ADD EDI, EAX
	Comparacion:
	MOV BL, [EDI]
	MOV AL, AUX
	CMP AL, 26d
	JE AsignarFin
	INC EDI
	INC AUX
	CMP BL, SimboloActual
	JLE Comparacion
	MOV SimboloActual, BL
	MOV AL, AUX
	MOV Posicion, AL
	JMP Comparacion
	AsignarFin:
	MOV BL, [ESI]
	CMP BL, 24H
	JE FinCalculo
	LEA EDI, Matriz
	MOV AL, Posicion
	DEC AL
	ADD EDI, EAX
	MOV [EDI], BL
	MOV AL, 26d
	ADD EDI, EAX
	MOV AL, 0d
	MOV [EDI],AL
	INC ESI
	jmp InicioCalculo
FinCalculo:	
RET
CalculoLetras ENDP

RomperCifrado PROC near
LEA ESI, Entrada
InicioLeerProb:
MOV AL, [ESI]
CMP AL,24h
JE finLeerCifr
CMP AL, 0H
JE finLeerCifr
	VerMin:
	CMP AL, "a"
	JAE VerMay
	JMP restarMayuscula
	VerMay:
	CMP AL, "z"
	JBE restar
	JMP restarMayuscula
	restar:
	SUB AL, 97d
	jmp IncrementarCont
	restarMayuscula:
	SUB AL, 65d
	jmp IncrementarCont
	IncrementarCont:
	MOV IndiceColumna, AL
	MapeoM 0d,IndiceColumna,26d,1d
	LEA EDI, Matriz
	MOV BL, AL
	XOR EAX, EAX
	MOV AL, BL
	ADD EDI, EAX
	MOV BL, [EDI]
	MOV AUX, BL
	INVOKE StdOut, ADDR AUX
	INC ESI
	jmp InicioLeerProb
	finLeerCifr:
RET
RomperCifrado ENDP

MostrarProbabilidad PROC near
LEA ESI, Matriz
MOV AL, 0H
MOV CONTADOR, AL
InicioProbab:
MOV AL, [ESI]
MOV AUX, AL
INVOKE StdOut, ADDR AUX
print chr$(": ")
XOR EAX, EAX
MOV AL, 26D
ADD ESI, EAX
MOV AL, [ESI]
SUB AL, 1D
MOV AUX, AL
print str$(Al)
print chr$("/")
MOV AL, ContarEntrada
MOV AUX, AL
print str$(AL)
print chr$(13,10)
MOV AL, 26d
SUB ESI, EAX
INC ESI
INC CONTADOR
MOV AL, CONTADOR
CMP AL, 26D
JE Final
jmp InicioProbab
Final:

RET
MostrarProbabilidad ENDP


END programa
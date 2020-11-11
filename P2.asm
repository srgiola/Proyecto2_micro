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
	opcion db 4 dup(0),0
	Mensaje dw 800 dup(0),0
	Clave DW 800 dup(0),0
	MensajeMod DW 100 dup ("$"),0
	ClaveMod DW 100 dup ("$"),0
	CaracteresM DB 100 dup(0),0 ;CANTIDAD CARACTERES EN MENSAJE
	CaracteresC DB 100 dup(0),0 ;CANTIDAD CARACTERES EN LA CLAVE
	prob db 12 dup(0),0
	
	Matriz DB 300 DUP("$"),0 
	str11 DB "Ingrese un mensaje",13,10,0
	str12 DB "Mensaje",13,10,0
	Probabilidad DB "EAOSNRILDUTCMPQYBHVGJFZKWX$",0
	Entrada DB 300 DUP("$"),0
	Fila DB 4 DUP(0),0
	Columna DB 4 DUP(0),0
	ABECEDAR DB 4 DUP(0),0
	AUX DB 4 DUP(0),0
	IndiceColumna db 4 DUP(0),0
	Posicion DB 4 DUP(0),0
	CONTADOR DB 4 DUP(0),0
	SALD DB 4 DUP(0),0
	SimboloActual DB 4 DUP(0),0

	MATRIZC DB 676 DUP(0)
	LETRAINI DB 41H
	LETRAFIN DB 5BH
	INDEXC DB 0H

.DATA?
	TMP DD ?
	TMP_C DW ?
	TMP_F DW ?
	CARACTER DB ?
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
		INVOKE StdIn, ADDR Clave, 99
		ImprimirCadena str6
		INVOKE StdIn, ADDR Mensaje, 99

		;CALL LimpiarMensaje
		;CALL LimpiarClave
		;CALL ContarCadena
		;CALL ContarCla
		;MOV AL,CaracteresM
		;CMP AL, CaracteresC
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
				CALL CIFRAR
				jmp finalizar
			CriptogramaVariacion:
				CALL CIFRAR2
				jmp finalizar
		jmp finalizar

	IngresarDes:
		jmp programa
	IngresarProb:

	JMP finalizar

	finalizar:
	INVOKE ExitProcess,0
;--------------------------- Procedimientos ---------------------------
	LimpiarMensaje PROC near
		LEA ESI, Mensaje
		LEA EDI, MensajeMod
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
				JBE Agregar
				jmp Incrementar
		Agregar:
			MOV [EDI], AX
			INC EDI
			JMP Incrementar
		Incrementar:
		INC ESI
		JMP IniciarMod
		finLimpiar:
	RET
	LimpiarMensaje ENDP

	LimpiarClave PROC near
		LEA ESI, Clave
		LEA EDI, ClaveMod
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
				JBE AgregarCla
				jmp IncrementarCla
		AgregarCla:
			MOV [EDI], AX
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
	LEA ESI, MensajeMod
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
	LEA EDI, ClaveMod
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

END programa
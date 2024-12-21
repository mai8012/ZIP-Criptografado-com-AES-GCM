package main

import (
	"archive/zip"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	// Necessário para PBKDF2
	"golang.org/x/crypto/pbkdf2"
)

// generateAESKey gera uma chave AES-256 (32 bytes) a partir de uma senha,
// usando PBKDF2 com um salt fixo (exemplo) e N iterações.
func generateAESKey(password string) []byte {
	salt := []byte("ow3yz5P{Z_N%04m$$Oim") // Em produção, ideal usar salt aleatório.
	iterations := 500_000                  // Ajuste conforme sua necessidade de segurança vs. performance.

	// Deriva 32 bytes usando SHA256
	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
	return key
}

// -----------------------------------------------------------------------------
// Criptografia AES-GCM para cada arquivo (entry) dentro do ZIP
// -----------------------------------------------------------------------------

// encrypt faz a criptografia AES-GCM de dados em memória.
func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar cipher AES: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("erro ao gerar nonce: %v", err)
	}

	// ciphertext = nonce || gcm.Seal(...)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// decrypt faz a descriptografia AES-GCM de dados em memória.
func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar cipher AES: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("dado criptografado muito curto")
	}

	nonce := ciphertext[:nonceSize]
	actualCipher := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, actualCipher, nil)
	if err != nil {
		return nil, fmt.Errorf("falha ao descriptografar: %v", err)
	}
	return plaintext, nil
}

// -----------------------------------------------------------------------------
// ZIP “não-padrão”: cada arquivo individualmente criptografado ao escrever
// -----------------------------------------------------------------------------

// addToZip adiciona arquivo(s) ou pasta(s) recursivamente no writer do ZIP.
// Cada arquivo é lido, criptografado e então escrito como entry do ZIP.
func addToZip(writer *zip.Writer, path, baseInZip string, aesKey []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("erro ao acessar '%s': %v", path, err)
	}

	if info.IsDir() {
		// Se for diretório, percorre recursivamente
		entries, err := os.ReadDir(path)
		if err != nil {
			return fmt.Errorf("erro ao ler diretório '%s': %v", path, err)
		}
		for _, e := range entries {
			subPath := filepath.Join(path, e.Name())
			subBase := filepath.Join(baseInZip, e.Name())
			err = addToZip(writer, subPath, subBase, aesKey)
			if err != nil {
				return err
			}
		}
	} else {
		// Se for arquivo, criptografa conteúdo e escreve no ZIP
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("erro ao abrir '%s': %v", path, err)
		}
		defer file.Close()

		plaintext, err := io.ReadAll(file)
		if err != nil {
			return fmt.Errorf("erro ao ler arquivo '%s': %v", path, err)
		}

		encryptedData, err := encrypt(plaintext, aesKey)
		if err != nil {
			return fmt.Errorf("erro ao criptografar '%s': %v", path, err)
		}

		zipEntry, err := writer.Create(baseInZip)
		if err != nil {
			return fmt.Errorf("erro ao criar entrada '%s' no ZIP: %v", baseInZip, err)
		}

		_, err = zipEntry.Write(encryptedData)
		if err != nil {
			return fmt.Errorf("erro ao escrever '%s' no ZIP: %v", path, err)
		}
	}
	return nil
}

// extractZip abre um ZIP “não-padrão” (onde cada arquivo está criptografado)
// e extrai os arquivos descriptografados no sistema local.
func extractZip(zipPath string, aesKey []byte) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err // deixaremos a verificação de erro para o chamador
	}
	defer reader.Close()

	for _, file := range reader.File {
		outPath := file.Name

		if file.FileInfo().IsDir() {
			// Cria a pasta
			if err := os.MkdirAll(outPath, file.Mode()); err != nil {
				return fmt.Errorf("erro ao criar diretório '%s': %v", outPath, err)
			}
			continue
		}

		// Garante que o diretório pai exista
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return fmt.Errorf("erro ao criar diretórios '%s': %v", outPath, err)
		}

		zippedFile, err := file.Open()
		if err != nil {
			return fmt.Errorf("erro ao abrir arquivo '%s' dentro do ZIP: %v", file.Name, err)
		}

		encryptedData, err := io.ReadAll(zippedFile)
		zippedFile.Close()
		if err != nil {
			return fmt.Errorf("erro ao ler dados do arquivo '%s': %v", file.Name, err)
		}

		// Descriptografa
		decryptedData, err := decrypt(encryptedData, aesKey)
		if err != nil {
			return fmt.Errorf("erro ao descriptografar '%s': %v", file.Name, err)
		}

		// Cria o arquivo no sistema
		outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			return fmt.Errorf("erro ao criar arquivo '%s': %v", outPath, err)
		}
		_, err = outFile.Write(decryptedData)
		outFile.Close()
		if err != nil {
			return fmt.Errorf("erro ao escrever '%s': %v", outPath, err)
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// main()
// -----------------------------------------------------------------------------

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	password := "UWfLezZH_gJXMAJY#S3:>)FW[B74/K#{Mo1s+£}Y}g^06z48" // define a senha desejada
	aesKey := generateAESKey(password)

MAIN_LOOP:
	for {
		var command string
		for {
			fmt.Println("\nDigite o comando desejado: zip/unzip")
			if !scanner.Scan() {

				fmt.Println("Encerrando o programa.")
				return
			}
			command = strings.ToLower(scanner.Text())

			if command == "zip" || command == "unzip" {
				break
			}
			fmt.Println("Comando inválido. Por favor, digite 'zip' ou 'unzip'.")
		}

		switch command {
		case "zip":
			var inputPath string
			for {
				fmt.Println("Digite o caminho do arquivo ou pasta para compactar (criptografado internamente):")
				if !scanner.Scan() {

					fmt.Println("Encerrando o programa.")
					return
				}
				inputPath = scanner.Text()

				if _, err := os.Stat(inputPath); os.IsNotExist(err) {
					fmt.Printf("O caminho '%s' não existe.\n", inputPath)
				} else {
					break
				}
			}

			// Cria o ZIP
			zipPath := filepath.Base(inputPath) + ".zip"
			zipFile, err := os.Create(zipPath)
			if err != nil {
				fmt.Printf("Erro ao criar arquivo ZIP '%s': %v\n", zipPath, err)
				continue
			}
			writer := zip.NewWriter(zipFile)

			// Adiciona arquivos criptografados
			err = addToZip(writer, inputPath, filepath.Base(inputPath), aesKey)
			if err != nil {
				writer.Close()
				zipFile.Close()
				os.Remove(zipPath)
				fmt.Printf("Erro ao compactar: %v\n", err)
				continue
			}

			// Fecha o ZIP
			if errClose := writer.Close(); errClose != nil {
				fmt.Printf("Erro ao fechar ZIP writer: %v\n", errClose)
			}
			if errClose := zipFile.Close(); errClose != nil {
				fmt.Printf("Erro ao fechar arquivo ZIP: %v\n", errClose)
			}

			fmt.Printf("Arquivo '%s' criado e cada arquivo interno está criptografado.\n", zipPath)

			// (Opcional) remover o original
			// os.RemoveAll(inputPath)

		case "unzip":
			var zipPath string
			for {
				fmt.Println("Digite o nome do arquivo ZIP (internamente criptografado) para descompactar:")
				if !scanner.Scan() {
					// EOF ou erro de leitura
					fmt.Println("Encerrando o programa.")
					return
				}
				zipPath = scanner.Text()

				if _, err := os.Stat(zipPath); os.IsNotExist(err) {
					fmt.Printf("O arquivo '%s' não existe.\n", zipPath)
				} else {
					break
				}
			}

			// Extrai
			err := extractZip(zipPath, aesKey)
			if err != nil {
				if strings.Contains(err.Error(), "not a valid zip file") {
					fmt.Println("Erro: o arquivo fornecido não é um ZIP válido ou está corrompido.")
				} else {
					fmt.Printf("Erro ao descompactar: %v\n", err)
				}
				continue
			}
			fmt.Printf("Arquivo ZIP '%s' descompactado e descriptografado com sucesso.\n", zipPath)

			// Remove o ZIP após extrair, se quiser
			if err := os.Remove(zipPath); err != nil {
				fmt.Printf("Aviso: não foi possível remover o arquivo '%s': %v\n", zipPath, err)
			}
		}

		for {
			fmt.Println("\nDeseja realizar outra operação? (sim/não)")
			if !scanner.Scan() {
				fmt.Println("Encerrando o programa.")
				return
			}
			nextAction := strings.ToLower(scanner.Text())

			if nextAction == "sim" || nextAction == "s" {
				// volta ao MAIN_LOOP (quebrando o loop de repetição)
				break
			} else if nextAction == "não" || nextAction == "nao" || nextAction == "n" {
				fmt.Println("Encerrando o programa.")
				break MAIN_LOOP
			} else {
				fmt.Println("Resposta inválida. Por favor, digite 'sim' ou 'não'.")
			}
		}
	}
}

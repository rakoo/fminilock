package main
/*
* miniLock-cli: A terminal utility to encrypt and decrypt files using the
* miniLock file encryption system
*/


import (
    "fmt"
    "io/ioutil"
  	"github.com/alecthomas/kingpin"
    "github.com/cathalgarvey/go-minilock"
    "github.com/howeyc/gopass"
)

var (
  encrypt = kingpin.Command("encrypt", "Encrypt a file.")
  decrypt = kingpin.Command("decrypt", "Decrypt a file.")

  efile = encrypt.Arg("file", "File to encrypt or decrypt.").Required().String()
  dfile = decrypt.Arg("file", "File to encrypt or decrypt.").Required().String()

  eUserEmail = encrypt.
    Arg("user-email", "Your email address. This need not be secret, but if this isn't *accurate* it must be *globally unique*, it is used for generating security.").
    Required().String()
  dUserEmail = decrypt.
    Arg("user-email", "Your email address. This need not be secret, but if this isn't *accurate* it must be *globally unique*, it is used for generating security.").
    Required().String()

  eOutputFileName = encrypt.Flag("output", "Name of output file. By default for encryption, this is input filename + '.minilock', and for decryption this is the indicated filename in the ciphertext. Warning: Right now this presents potential security hazards!").
    Short('o').Default("NOTGIVEN").String()
  dOutputFileName = decrypt.Flag("output", "Name of output file. By default for encryption, this is input filename + '.minilock', and for decryption this is the indicated filename in the ciphertext. Warning: Right now this presents potential security hazards!").
    Short('o').Default("NOTGIVEN").String()

  recipients = encrypt.Arg("recipients", "One or more miniLock IDs to add to encrypted file.").Strings()
  encryptToSelf = encrypt.Flag("encrypt-to-self", "Whether to add own ID to recipients list, default is True.").
    Short('s').Default("true").Bool()

)

func main() {
  kingpin.UsageTemplate(kingpin.DefaultUsageTemplate).Author("Cathal Garvey")
	//kingpin.CommandLine.Help = "miniLock-cli: The miniLock encryption system for terminal/scripted use."
	switch kingpin.Parse() {
	case "encrypt":
		kingpin.FatalIfError(encryptFile(), "Failed to encrypt..")

	case "decrypt": {
		kingpin.FatalIfError(decryptFile(), "Failed to decrypt..")
	}
  default : {
    fmt.Println("No subcommand provided..")
  }
  }
}

func encryptFile() error {
//EncryptFileContents(filename string, fileContents []byte, sender *taber.Keys, recipients ...*taber.Keys) (miniLockContents []byte, err error)
  f, err := ioutil.ReadFile(*efile)
  if err != nil {
    return err
  }
  pp := getPass()
  // minilock.EncryptFileContentsWithStrings(filename string, fileContents []byte, senderEmail, senderPassphrase string, sendToSender bool, recipientIDs... string)  (miniLockContents []byte, err error){
  mlfilecontents, err := minilock.EncryptFileContentsWithStrings(*efile, f, *eUserEmail, pp, *encryptToSelf, *recipients...)
  if err != nil {
    return err
  }
  if *eOutputFileName == "NOTGIVEN" {
    *eOutputFileName = *efile + ".minilock"
  }
  userKey, err := minilock.GenerateKey(*eUserEmail, pp)
  if err != nil {
    return err
  }
  userID, err := userKey.EncodeID()
  if err != nil {
    return err
  }
  fmt.Println("File encrypted using ID: '"+userID+"'")
  return ioutil.WriteFile(*eOutputFileName, mlfilecontents, 33204)
}

func decryptFile() error {
//DecryptFileContents(file_contents []byte, recipientKey *taber.Keys) (senderID, filename string, contents []byte, err error) {
  pp := getPass()
  userKey, err := minilock.GenerateKey(*dUserEmail, pp)
  if err != nil {
    return err
  }
  mlfilecontents, err := ioutil.ReadFile(*dfile)
  if err != nil {
    return err
  }
  sender, filename, filecontents, err := minilock.DecryptFileContents(mlfilecontents, userKey)
  if err != nil {
    return err
  }
  if *dOutputFileName != "NOTGIVEN" {
    filename = *dOutputFileName
  }
  fmt.Println("File received from id '"+sender+"', saving to", filename)
  return ioutil.WriteFile(filename, filecontents, 33204)
  return nil
}

func getPass() string {
  fmt.Print("Enter password: ")
  return string(gopass.GetPasswd())
}

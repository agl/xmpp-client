package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/agl/xmpp-client/xmpp"

	"github.com/agl/xmpp-client/xlib"
)

// promptForForm runs an XEP-0004 form and collects responses from the user.
func promptForForm(xio xlib.XIO, user, password, title, instructions string, fields []interface{}) error {
	xio.Info("The server has requested the following information. Text that has come from the server will be shown in red.")

	var tmpDir string

	showMediaEntries := func(questionNumber int, medias [][]xmpp.Media) {
		if len(medias) == 0 {
			return
		}

		xio.Write("The following media blobs have been provided by the server with this question:\n")
		for i, media := range medias {
			for j, rep := range media {
				if j == 0 {
					xio.Write(fmt.Sprintf("  %d. ", i+1))
				} else {
					xio.Write("     ")
				}
				xio.Write(fmt.Sprintf("Data of type %s", xio.FormStringForPrinting(rep.MIMEType)))
				if len(rep.URI) > 0 {
					xio.Write(fmt.Sprintf(" at %s\n", xio.FormStringForPrinting(rep.URI)))
					continue
				}

				var fileExt string
				switch rep.MIMEType {
				case "image/png":
					fileExt = "png"
				case "image/jpeg":
					fileExt = "jpeg"
				}

				if len(tmpDir) == 0 {
					var err error
					if tmpDir, err = ioutil.TempDir("", "xmppclient"); err != nil {
						xio.Write(", but failed to create temporary directory in which to save it: " + err.Error() + "\n")
						continue
					}
				}

				filename := filepath.Join(tmpDir, fmt.Sprintf("%d-%d-%d", questionNumber, i, j))
				if len(fileExt) > 0 {
					filename = filename + "." + fileExt
				}
				out, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
				if err != nil {
					xio.Write(", but failed to create file in which to save it: " + err.Error() + "\n")
					continue
				}
				out.Write(rep.Data)
				out.Close()

				xio.Write(", saved in " + filename + "\n")
			}
		}

		xio.Write("\n")
	}

	var err error
	if len(title) > 0 {
		xio.Write(fmt.Sprintf("Title: %s\n", xio.FormStringForPrinting(title)))
	}
	if len(instructions) > 0 {
		xio.Write(fmt.Sprintf("Instructions: %s\n", xio.FormStringForPrinting(instructions)))
	}

	questionNumber := 0
	for _, field := range fields {
		questionNumber++
		xio.Write("\n")

		switch field := field.(type) {
		case *xmpp.FixedFormField:
			xio.Write(xio.FormStringForPrinting(field.Text))
			xio.Write("\n")
			questionNumber--

		case *xmpp.BooleanFormField:
			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)
			xio.SetPrompt("Please enter yes, y, no or n: ")

		TryAgain:
			for {
				answer, err := xio.ReadLine()
				if err != nil {
					return err
				}
				switch answer {
				case "yes", "y":
					field.Result = true
				case "no", "n":
					field.Result = false
				default:
					continue TryAgain
				}
				break
			}

		case *xmpp.TextFormField:
			switch field.Label {
			case "CAPTCHA web page":
				if strings.HasPrefix(field.Default, "http") {
					// This is a oddity of jabber.ccc.de and maybe
					// others. The URL for the capture is provided
					// as the default answer to a question. Perhaps
					// that was needed with some clients. However,
					// we support embedded media and it's confusing
					// to ask the question, so we just print the
					// URL.
					xio.Write(fmt.Sprintf("CAPTCHA web page (only if not provided below): %s\n", xio.FormStringForPrinting(field.Default)))
					questionNumber--
					continue
				}

			case "User":
				field.Result = user
				questionNumber--
				continue

			case "Password":
				field.Result = password
				questionNumber--
				continue
			}

			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			if len(field.Default) > 0 {
				xio.Write(fmt.Sprintf("Please enter response or leave blank for the default, which is '%s'\n", xio.FormStringForPrinting(field.Default)))
			} else {
				xio.Write("Please enter response")
			}
			xio.SetPrompt("> ")
			if field.Private {
				field.Result, err = xio.ReadPassword("> ")
			} else {
				field.Result, err = xio.ReadLine()
			}
			if err != nil {
				return err
			}
			if len(field.Result) == 0 {
				field.Result = field.Default
			}

		case *xmpp.MultiTextFormField:
			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			xio.Write("Please enter one or more responses, terminated by an empty line\n")
			xio.SetPrompt("> ")

			for {
				line, err := xio.ReadLine()
				if err != nil {
					return err
				}
				if len(line) == 0 {
					break
				}
				field.Results = append(field.Results, line)
			}

		case *xmpp.SelectionFormField:
			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			for i, opt := range field.Values {
				xio.Write(fmt.Sprintf("  %d. %s\n\n", i+1, xio.FormStringForPrinting(opt)))
			}
			xio.SetPrompt("Please enter the number of your selection: ")

		TryAgain2:
			for {
				answer, err := xio.ReadLine()
				if err != nil {
					return err
				}
				answerNum, err := strconv.Atoi(answer)
				answerNum--
				if err != nil || answerNum < 0 || answerNum >= len(field.Values) {
					xio.Write("Cannot parse that reply. Try again.")
					continue TryAgain2
				}

				field.Result = answerNum
				break
			}

		case *xmpp.MultiSelectionFormField:
			xio.Write(fmt.Sprintf("%d. %s\n\n", questionNumber, xio.FormStringForPrinting(field.Label)))
			showMediaEntries(questionNumber, field.Media)

			for i, opt := range field.Values {
				xio.Write(fmt.Sprintf("  %d. %s\n\n", i+1, xio.FormStringForPrinting(opt)))
			}
			xio.SetPrompt("Please enter the numbers of zero or more of the above, separated by spaces: ")

		TryAgain3:
			for {
				answer, err := xio.ReadLine()
				if err != nil {
					return err
				}

				var candidateResults []int
				answers := strings.Fields(answer)
				for _, answerStr := range answers {
					answerNum, err := strconv.Atoi(answerStr)
					answerNum--
					if err != nil || answerNum < 0 || answerNum >= len(field.Values) {
						xio.Write("Cannot parse that reply. Please try again.")
						continue TryAgain3
					}
					for _, other := range candidateResults {
						if answerNum == other {
							xio.Write("Cannot have duplicates. Please try again.")
							continue TryAgain3
						}
					}
					candidateResults = append(candidateResults, answerNum)
				}

				field.Results = candidateResults
				break
			}
		}
	}

	if len(tmpDir) > 0 {
		os.RemoveAll(tmpDir)
	}

	return nil
}

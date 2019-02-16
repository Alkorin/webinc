package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Alkorin/gocui"
	log "github.com/sirupsen/logrus"
)

var logo = []string{
	`__        __   _    ___        ____ `,
	`\ \      / /__| |__|_ _|_ __  / ___|`,
	` \ \ /\ / / _ \ '_ \| || '_ \| |    `,
	`  \ V  V /  __/ |_) | || | | | |___ `,
	`   \_/\_/ \___|_.__/___|_| |_|\____|`,
}

type GoCUI struct {
	*gocui.Gui
	conversation *Conversation

	spacesMutex                          sync.RWMutex
	spacesMap                            map[string]int
	spacesList                           []GuiSpace
	currentSpaceIndex                    int
	currentSpaceNewMessagesSeparatorTime time.Time
	logger                               *log.Entry
}

type GuiSpace struct {
	*Space
	Highlight bool
}

func (g *GuiSpace) DisplayName() string {
	name := g.Space.DisplayName
	if g.Team != nil {
		name = g.Team.DisplayName + "/" + name
	}
	return name

}

func NewGoCUI(c *Conversation) (*GoCUI, error) {
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		return nil, err
	}

	gui := &GoCUI{
		Gui:               g,
		conversation:      c,
		currentSpaceIndex: -1,
		spacesMap:         make(map[string]int),
		logger:            log.WithField("type", "Gui"),
	}
	gui.Cursor = true
	gui.SetManagerFunc(gui.layout)
	gui.SetResizeFunc(func(g *gocui.Gui, x, y int) error {
		// Update messages if size changed
		gui.updateMessages()
		return nil
	})

	if err := gui.keybindings(gui.Gui); err != nil {
		return nil, err
	}

	c.AddNewSpaceEventHandler(gui.NewSpaceHandler)
	c.AddRemoveSpaceEventHandler(gui.RemoveSpaceHandler)
	c.AddNewActivityEventHandler(gui.NewActivityHandler)

	return gui, nil
}

func (gui *GoCUI) IsCurrentSpace(id string) bool {
	if gui.currentSpaceIndex == -1 {
		return false
	}
	return gui.spacesList[gui.currentSpaceIndex].Id == id

}

func (gui *GoCUI) Start() error {
	if err := gui.MainLoop(); err != nil && err != gocui.ErrQuit {
		return err
	}
	gui.Close()
	return nil
}

func (gui *GoCUI) NewSpaceHandler(s *Space) {
	gui.spacesMutex.Lock()
	pos := len(gui.spacesList)
	gui.spacesList = append(gui.spacesList, GuiSpace{Space: s})
	gui.spacesMap[s.Id] = pos
	gui.spacesMutex.Unlock()
	gui.updateSpaceList()
}

func (gui *GoCUI) RemoveSpaceHandler(s *Space) {
	gui.spacesMutex.Lock()

	if spaceIndex, ok := gui.spacesMap[s.Id]; ok {
		// Remove space from list
		gui.spacesList = append(gui.spacesList[:spaceIndex], gui.spacesList[spaceIndex+1:]...)

		// Recompute map
		gui.spacesMap = make(map[string]int)
		for i, v := range gui.spacesList {
			gui.spacesMap[v.Id] = i
		}

		gui.spacesMutex.Unlock()

		// Update UI
		if spaceIndex == gui.currentSpaceIndex {
			gui.moveToSpace(gui.currentSpaceIndex)
		} else {
			gui.updateSpaceList()
		}
	} else {
		gui.spacesMutex.Unlock()
	}
}

func (gui *GoCUI) NewActivityHandler(s *Space, a *Activity) {
	gui.spacesMutex.RLock()
	defer gui.spacesMutex.RUnlock()

	if a.Verb == "create" {
		spaceIndex, ok := gui.spacesMap[s.Id]
		if ok {
			gui.moveToSpace(spaceIndex)
		}
	} else if a.Verb == "acknowledge" && !gui.IsCurrentSpace(a.Target.Id) {
		gui.updateSpaceList()
	} else if a.Verb == "post" || a.Verb == "share" {
		spaceIndex := gui.spacesMap[s.Id]
		if spaceIndex != gui.currentSpaceIndex {
			for _, v := range a.Object.Mentions.Items {
				if v.Id == gui.conversation.device.UserID {
					gui.spacesList[spaceIndex].Highlight = true
				}
			}
			gui.updateSpaceList()
		} else {
			gui.updateMessages()
		}
	}
}

func (gui *GoCUI) quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func (gui *GoCUI) keybindings(g *gocui.Gui) error {
	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, gui.quit); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyCtrlN, gocui.ModNone, gui.nextSpace); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyCtrlP, gocui.ModNone, gui.previousSpace); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyCtrlW, gocui.ModNone, func(*gocui.Gui, *gocui.View) error { gui.leaveCurrentSpace(); return nil }); err != nil {
		return err
	}
	if err := g.SetKeybinding("help", gocui.KeyEnter, gocui.ModNone, func(*gocui.Gui, *gocui.View) error { return gui.hideHelp() }); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyPgup, gocui.ModNone, gui.msgUp); err != nil {
		return err
	}
	if err := g.SetKeybinding("", gocui.KeyPgdn, gocui.ModNone, gui.msgDown); err != nil {
		return err
	}
	return nil
}

func (gui *GoCUI) nextSpace(g *gocui.Gui, v *gocui.View) error {
	gui.moveToSpace(gui.currentSpaceIndex + 1)
	return nil
}

func (gui *GoCUI) previousSpace(g *gocui.Gui, v *gocui.View) error {
	gui.moveToSpace(gui.currentSpaceIndex - 1)
	return nil
}

func (gui *GoCUI) msgUp(g *gocui.Gui, v *gocui.View) error {
	return gui.msgScroll(-5)
}

func (gui *GoCUI) msgDown(g *gocui.Gui, v *gocui.View) error {
	return gui.msgScroll(5)
}

func (gui *GoCUI) msgScroll(delta int) error {
	v, _ := gui.View("messages")

	// Current position
	_, viewHeight := v.Size()
	ox, oy := v.Origin()

	if viewHeight+oy+delta > len(v.ViewBufferLines())-1 {
		// We are at the bottom, enable Autoscroll
		v.Autoscroll = true
	} else {
		// Set autoscroll to false and scroll.
		v.Autoscroll = false
		v.SetOrigin(ox, oy+delta)
	}
	gui.updateSpaceStatus()
	return nil
}

func (gui *GoCUI) hideHelp() error {
	gui.SetViewOnTop("messages")
	gui.SetCurrentView("cmd")
	gui.Cursor = true
	return nil
}

func (gui *GoCUI) showHelp() error {
	gui.SetViewOnTop("help")
	gui.SetCurrentView("help")
	gui.Cursor = false
	return nil
}

func (gui *GoCUI) leaveCurrentSpace() {
	if gui.currentSpaceIndex != -1 {
		gui.conversation.LeaveSpace(gui.spacesList[gui.currentSpaceIndex].Space)
	}
}

func (gui *GoCUI) moveToSpace(i int) {
	gui.spacesMutex.RLock()
	defer gui.spacesMutex.RUnlock()

	// No spaces
	if len(gui.spacesList) == 0 {
		return
	}

	// Wrap
	if i < 0 {
		i = len(gui.spacesList) - 1
	} else if i >= len(gui.spacesList) {
		i = 0
	}

	gui.currentSpaceIndex = i
	newSpace := gui.spacesList[gui.currentSpaceIndex]
	gui.currentSpaceNewMessagesSeparatorTime = newSpace.LastSeenActivityDate
	if newSpace.HasUnseenActivities() {
		gui.spacesList[gui.currentSpaceIndex].SendAcknowledge()
	}

	// Reset flags
	gui.spacesList[i].Highlight = false

	// Force go to bottom for messages
	v, _ := gui.View("messages")
	v.Autoscroll = true

	// Refresh
	gui.updateMessages()
	gui.updateSpaceStatus()
	gui.updateSpaceList()
}

func (gui *GoCUI) sendMessage(msg string) {
	gui.spacesMutex.RLock()
	defer gui.spacesMutex.RUnlock()

	if msg[0] == '/' {
		logger := gui.logger.WithField("cmd", msg)
		logger.Trace("Exectuting command")
		if msg[1:] == "help" {
			gui.showHelp()
		}
		if msg[1:] == "quit" {
			gui.Update(func(g *gocui.Gui) error {
				return gocui.ErrQuit
			})
		}
		if strings.HasPrefix(msg[1:], "win ") {
			i, err := strconv.Atoi(msg[5:])
			if err == nil && i > 0 && i <= len(gui.spacesList) {
				gui.moveToSpace(i - 1)
			} else {
				// Try to find a space with a matching name
				toSearch := strings.ToLower(msg[5:])
				for i, v := range gui.spacesList {
					if strings.Contains(strings.ToLower(v.DisplayName()), toSearch) {
						gui.moveToSpace(i)
						break
					}
				}
			}
		}
		if msg[1:] == "leave" {
			gui.leaveCurrentSpace()
		}
		if strings.HasPrefix(msg[1:], "create ") {
			gui.conversation.CreateSpace(msg[8:])
		}
		// Unknown command
	} else if gui.currentSpaceIndex != -1 {
		gui.spacesList[gui.currentSpaceIndex].SendMessage(msg)
	}
}

func (gui *GoCUI) updateSpaceList() {
	gui.Update(func(g *gocui.Gui) error {
		gui.spacesMutex.RLock()
		defer gui.spacesMutex.RUnlock()

		v, err := g.View("spaces")
		if err != nil {
			return err
		}
		v.Clear()
		for i, s := range gui.spacesList {
			color := "34"

			if i == gui.currentSpaceIndex {
				color = "37;44"
			} else if s.Highlight {
				color = "33"
			} else if s.HasUnseenActivities() {
				color = "32"
			}

			fmt.Fprintf(v, "\033[32m%2d\033[0m.\033[%sm%s\033[0m\n", i+1, color, s.DisplayName())
		}

		return nil
	})
}

func (gui *GoCUI) updateMessages() {
	gui.Update(func(g *gocui.Gui) error {
		gui.spacesMutex.RLock()
		defer gui.spacesMutex.RUnlock()

		v, err := g.View("messages")
		if err != nil {
			return err
		}

		v.Clear()
		v.SetOrigin(0, 0)

		hasPrintNewMessagesSeparator := false

		if gui.currentSpaceIndex == -1 {
			fmt.Fprintln(v, "")
			fmt.Fprintln(v, "")

			width, _ := v.Size()

			for _, l := range logo {
				fmt.Fprint(v, strings.Repeat(" ", (width-len(l))/2))
				fmt.Fprintln(v, l)
			}

			fmt.Fprintln(v, "")
			l := fmt.Sprintf("WebInC - Webex Teams in Console - %s", buildVersion)
			fmt.Fprint(v, strings.Repeat(" ", (width-len(l))/2))
			fmt.Fprintln(v, l)
		} else {
			space := gui.spacesList[gui.currentSpaceIndex]
			for _, a := range space.Activities {
				if a.Published.After(gui.currentSpaceNewMessagesSeparatorTime) && !hasPrintNewMessagesSeparator {
					hasPrintNewMessagesSeparator = true
					separator := " New messages "
					width, _ := v.Size()
					fmt.Fprint(v, strings.Repeat("-", (width-len(separator))/2))
					fmt.Fprint(v, separator)
					fmt.Fprint(v, strings.Repeat("-", width-len(separator)-(width-len(separator))/2))
				}
				if a.Verb == "post" {
					fmt.Fprintf(v, "%s %s> %s\n", a.Published.Format("15:04:05"), a.Actor.DisplayName, a.Object.DisplayName)
				} else if a.Verb == "share" {
					fmt.Fprintf(v, "%s %s has shared a content of type %q\n", a.Published.Format("15:04:05"), a.Actor.DisplayName, a.Object.ContentCategory)
					if a.Object.DisplayName != "" {
						fmt.Fprintf(v, "%s %s> %s\n", a.Published.Format("15:04:05"), a.Actor.DisplayName, a.Object.DisplayName)
					}
				}
			}
		}

		return nil
	})

}

func (gui *GoCUI) updateSpaceStatus() {
	gui.Update(func(g *gocui.Gui) error {
		gui.spacesMutex.RLock()
		defer gui.spacesMutex.RUnlock()

		v, _ := g.View("spaceStatus")
		v.Clear()

		if gui.currentSpaceIndex != -1 {
			space := gui.spacesList[gui.currentSpaceIndex]

			fmt.Fprintf(v, "[%s]", space.DisplayName())

			msgView, _ := g.View("messages")
			if !msgView.Autoscroll {
				_, viewHeight := msgView.Size()
				_, oy := msgView.Origin()
				nbLines := len(msgView.ViewBufferLines())

				moreLines := nbLines - viewHeight - oy
				fmt.Fprintf(v, " -MORE(%d)-", moreLines)
			}
		}
		return nil
	})
}

func (gui *GoCUI) layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if _, err := g.SetView("spaces", -1, -1, 25, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
	}
	if v, err := g.SetView("help", 25, -1, maxX, maxY-2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Frame = false
		fmt.Fprintf(v, " - WebInC %s HELP -\n", buildVersion)
		fmt.Fprintln(v, "")
		fmt.Fprintln(v, "List of commands:")
		fmt.Fprintln(v, " \033[32m/create name \033[0mCreate a new space with name \033[32mname\033[0m")
		fmt.Fprintln(v, " \033[32m/leave       \033[0mLeave the current space")
		fmt.Fprintln(v, " \033[32m/help        \033[0mDisplay this help")
		fmt.Fprintln(v, " \033[32m/win number  \033[0mJump to space with number \033[32mnumber\033[0m")
		fmt.Fprintln(v, " \033[32m/win name    \033[0mJump to space with name contains \033[32mname\033[0m")
		fmt.Fprintln(v, " \033[32m/quit	       \033[0mQuit the application")
		fmt.Fprintln(v, "")
		fmt.Fprintln(v, "List of keyboard shortcuts:")
		fmt.Fprintln(v, " \033[32m^P    \033[0mPrevious space")
		fmt.Fprintln(v, " \033[32m^N    \033[0mNext space")
		fmt.Fprintln(v, " \033[32m^W    \033[0mLeave the current space")
		fmt.Fprintln(v, " \033[32m^C    \033[0mQuit the application")
		fmt.Fprintln(v, " \033[32m^A    \033[0mGo to the beginning of line")
		fmt.Fprintln(v, " \033[32m^E    \033[0mGo to the end of line")
		fmt.Fprintln(v, " \033[32m^U    \033[0mDelete the beginning of line")
		fmt.Fprintln(v, " \033[32m^K    \033[0mDelete the end of line")
		fmt.Fprintln(v, "")
		fmt.Fprintln(v, "Press ENTER to close")
	}
	if v, err := g.SetView("messages", 25, -1, maxX, maxY-2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Wrap = true
		v.Autoscroll = true
		v.Frame = false
	}
	if v, err := g.SetView("spaceStatus", 25, maxY-3, maxX, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Wrap = true
		v.Frame = false
		v.BgColor = gocui.ColorBlue
	}
	if v, err := g.SetView("cmd", 25, maxY-2, maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Frame = false
		v.Editable = true
		v.Editor = NewHistoryEditor(gui.sendMessage)
		if _, err := g.SetCurrentView("cmd"); err != nil {
			return err
		}
	}

	return nil
}

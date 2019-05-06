package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/qantik/qrgo"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/byzcoin/bcadmin/lib"
	"go.dedis.ch/cothority/v3/byzcoin/contracts"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	_ "go.dedis.ch/cothority/v3/personhood"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/app"
	"go.dedis.ch/onet/v3/cfgpath"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"gopkg.in/urfave/cli.v1"
)

func init() {
	network.RegisterMessages(&darc.Darc{}, &darc.Identity{}, &darc.Signer{})
}

var cmds = cli.Commands{
	{
		Name:      "create",
		Usage:     "create a ledger",
		Aliases:   []string{"c"},
		ArgsUsage: "[roster.toml]",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "roster, r",
				Usage: "the roster of the cothority that will host the ledger",
			},
			cli.DurationFlag{
				Name:  "interval, i",
				Usage: "the block interval for this ledger",
				Value: 5 * time.Second,
			},
		},
		Action: create,
	},

	{
		Name:      "link",
		Usage:     "link to existing ledger",
		Aliases:   []string{"ln"},
		ArgsUsage: "roster.toml [bcid]",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "admindarc, ad",
				Usage: "the admin darc that has 'evolve_unrestricted'",
			},
			cli.StringFlag{
				Name:  "adminpub, ap",
				Usage: "the public key of the admin to use",
			},
		},
		Action: link,
	},

	{
		Name:      "latest",
		Usage:     "show the latest block in the chain",
		Aliases:   []string{"s"},
		ArgsUsage: "[bc.cfg]",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:   "bc",
				EnvVar: "BC",
				Usage:  "the ByzCoin config to use",
			},
			cli.IntFlag{
				Name:  "server",
				Usage: "which server number from the roster to contact (default: 0)",
				Value: 0,
			},
			cli.BoolFlag{
				Name:  "update",
				Usage: "update the ByzCoin config file with the fetched roster",
			},
		},
		Action: latest,
	},

	{
		Name:    "debug",
		Usage:   "interact with byzcoin for debugging",
		Aliases: []string{"d"},
		Subcommands: cli.Commands{
			{
				Name:      "replay",
				Usage:     "Replay a chain and check the global state is consistent",
				Action:    debugReplay,
				ArgsUsage: "URL",
			},
			{
				Name:   "list",
				Usage:  "Lists all byzcoin instances",
				Action: debugList,
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "verbose, v",
						Usage: "print more information of the instances",
					},
				},
				ArgsUsage: "(ip:port | group.toml)",
			},
			{
				Name:  "dump",
				Usage: "dumps a given byzcoin instance",
				Flags: []cli.Flag{
					cli.BoolFlag{
						Name:  "verbose, v",
						Usage: "print more information of the instances",
					},
				},
				Action:    debugDump,
				ArgsUsage: "ip:port byzcoin-id",
			},
			{
				Name:      "remove",
				Usage:     "removes a given byzcoin instance",
				Action:    debugRemove,
				ArgsUsage: "private.toml byzcoin-id",
			},
		},
	},

	{
		Name:      "mint",
		Usage:     "mint coins on account",
		ArgsUsage: "bc-xxx.cfg key-xxx.cfg public-key #coins",
		Action:    mint,
	},

	{
		Name:    "roster",
		Usage:   "change the roster of the ByzCoin",
		Aliases: []string{"r"},
		Subcommands: cli.Commands{
			{
				Name:      "add",
				ArgsUsage: "bc-xxx.cfg key-xxx.cfg public.toml",
				Usage:     "Add a new node to the roster",
				Action:    rosterAdd,
			},
			{
				Name:      "del",
				ArgsUsage: "bc-xxx.cfg key-xxx.cfg public.toml",
				Usage:     "Remove a node from the roster",
				Action:    rosterDel,
			},
			{
				Name:      "leader",
				ArgsUsage: "bc-xxx.cfg key-xxx.cfg public.toml",
				Usage:     "Set a specific node to be the leader",
				Action:    rosterLeader,
			},
		},
	},

	{
		Name:      "config",
		Usage:     "update the config",
		ArgsUsage: "bc-xxx.cfg key-xxx.cfg",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "interval",
				Usage: "change the interval",
			},
			cli.IntFlag{
				Name:  "blockSize",
				Usage: "adjust the maximum block size",
			},
		},
		Action: config,
	},

	{
		Name:    "key",
		Usage:   "generates a new keypair and prints the public key in the stdout",
		Aliases: []string{"k"},
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "save",
				Usage: "file in which the user wants to save the public key instead of printing it",
			},
			cli.StringFlag{
				Name:  "print",
				Usage: "print the private and public key",
			},
		},
		Action: key,
	},

	{
		Name:    "darc",
		Usage:   "tool used to manage darcs",
		Aliases: []string{"d"},
		Subcommands: cli.Commands{
			{
				Name:   "show",
				Usage:  "Show a DARC",
				Action: darcShow,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:   "bc",
						EnvVar: "BC",
						Usage:  "the ByzCoin config to use (required)",
					},
					cli.StringFlag{
						Name:  "darc",
						Usage: "the darc to show (no default)",
					},
				},
			},
			{
				Name:   "add",
				Usage:  "Add a new DARC with default rules.",
				Action: darcAdd,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:   "bc",
						EnvVar: "BC",
						Usage:  "the ByzCoin config to use (required)",
					},
					cli.StringFlag{
						Name:  "sign, signer",
						Usage: "public key which will sign the DARC spawn request (default: the ledger admin identity)",
					},
					cli.StringFlag{
						Name:  "darc",
						Usage: "DARC with the right to create a new DARC (default is the admin DARC)",
					},
					cli.StringFlag{
						Name:  "owner",
						Usage: "the identity who is allowed to sign and evolve it (default is a new key pair)",
					},
					cli.BoolFlag{
						Name:  "unrestricted",
						Usage: "add the invoke:evolve_unrestricted rule",
					},
					cli.StringFlag{
						Name:  "out_id",
						Usage: "output file for the darc id (optional)",
					},
					cli.StringFlag{
						Name:  "out_key",
						Usage: "output file for the darc key (optional)",
					},
					cli.StringFlag{
						Name:  "desc",
						Usage: "the description for the new DARC (default: random)",
					},
				},
			},
			{
				Name:   "rule",
				Usage:  "Edit DARC rules.",
				Action: darcRule,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:   "bc",
						EnvVar: "BC",
						Usage:  "the ByzCoin config to use (required)",
					},
					cli.StringFlag{
						Name:  "darc",
						Usage: "the DARC to update (no default)",
					},
					cli.StringFlag{
						Name:  "rule",
						Usage: "the rule to be added, updated or deleted",
					},
					cli.StringFlag{
						Name:  "sign",
						Usage: "public key of the signing entity (default is the admin public key)",
					},
					cli.StringFlag{
						Name:  "identity",
						Usage: "the identity of the signer who will be allowed to use the rule",
					},
					cli.BoolFlag{
						Name:  "replace",
						Usage: "if this rule already exists, replace it with this new one",
					},
					cli.BoolFlag{
						Name:  "delete",
						Usage: "delete the rule",
					},
				},
			},
		},
	},

	{
		Name:    "qr",
		Usage:   "generates a QRCode containing the description of the BC Config",
		Aliases: []string{"qrcode"},
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:   "bc",
				EnvVar: "BC",
				Usage:  "the ByzCoin config to use (required)",
			},
			cli.BoolFlag{
				Name:  "admin",
				Usage: "If specified, the QR Code will contain the admin keypair",
			},
		},
		Action: qrcode,
	},
}

var cliApp = cli.NewApp()

// getDataPath is a function pointer so that tests can hook and modify this.
var getDataPath = cfgpath.GetDataPath

var gitTag = "dev"

func init() {
	cliApp.Name = "bcadmin"
	cliApp.Usage = "Create ByzCoin ledgers and grant access to them."
	cliApp.Version = gitTag
	cliApp.Commands = cmds
	cliApp.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
		cli.StringFlag{
			Name:   "config, c",
			EnvVar: "BC_CONFIG",
			Value:  getDataPath(cliApp.Name),
			Usage:  "path to configuration-directory",
		},
	}
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		lib.ConfigPath = c.String("config")
		return nil
	}
}

func main() {
	rand.Seed(time.Now().Unix())
	err := cliApp.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func create(c *cli.Context) error {
	fn := c.String("roster")
	if fn == "" {
		fn = c.Args().First()
		if fn == "" {
			return errors.New("roster argument or --roster flag is required")
		}
	}
	r, err := lib.ReadRoster(fn)
	if err != nil {
		return err
	}

	interval := c.Duration("interval")

	owner := darc.NewSignerEd25519(nil, nil)

	req, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, r, []string{"spawn:longTermSecret"}, owner.Identity())
	if err != nil {
		log.Error(err)
		return err
	}
	req.BlockInterval = interval

	_, resp, err := byzcoin.NewLedger(req, false)
	if err != nil {
		return err
	}

	cfg := lib.Config{
		ByzCoinID:     resp.Skipblock.SkipChainID(),
		Roster:        *r,
		AdminDarc:     req.GenesisDarc,
		AdminIdentity: owner.Identity(),
	}
	fn, err = lib.SaveConfig(cfg)
	if err != nil {
		return err
	}

	err = lib.SaveKey(owner)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(c.App.Writer, "Created ByzCoin with ID %x.\n", cfg.ByzCoinID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.App.Writer, "export BC=\"%v\"\n", fn)
	if err != nil {
		return err
	}

	// For the tests to use.
	c.App.Metadata["BC"] = fn

	return nil
}

func link(c *cli.Context) error {
	if c.NArg() < 1 {
		return errors.New("please give the following args: roster.toml [bcid]")
	}
	r, err := lib.ReadRoster(c.Args().First())
	if err != nil {
		return err
	}

	scl := skipchain.NewClient()
	if c.NArg() == 1 {
		log.Info("Fetching all byzcoin-ids from the roster")
		var scIDs []skipchain.SkipBlockID
		for _, si := range r.List {
			reply, err := scl.GetAllSkipChainIDs(si)
			if err != nil {
				log.Warn("Couldn't contact", si.Address, err)
			} else {
				scIDs = append(scIDs, reply.IDs...)
				log.Infof("Got %d id(s) from %s", len(reply.IDs), si.Address)
			}
		}
		sort.Slice(scIDs, func(i, j int) bool {
			return bytes.Compare(scIDs[i], scIDs[j]) < 0
		})
		for i := len(scIDs) - 1; i > 0; i-- {
			if scIDs[i].Equal(scIDs[i-1]) {
				scIDs = append(scIDs[0:i], scIDs[i+1:]...)
			}
		}
		log.Info("All IDs available in this roster:")
		for _, id := range scIDs {
			log.Infof("%x", id[:])
		}
	} else {
		id, err := hex.DecodeString(c.Args().Get(1))
		if err != nil || len(id) != 32 {
			return errors.New("second argument is not a valid ID")
		}
		var cl *byzcoin.Client
		var cc *byzcoin.ChainConfig
		for _, si := range r.List {
			reply, err := scl.GetAllSkipChainIDs(si)
			if err != nil {
				log.Warn("Got error while asking", si.Address, "for skipchains")
			}
			found := false
			for _, idc := range reply.IDs {
				if idc.Equal(id) {
					found = true
					break
				}
			}
			if found {
				cl = byzcoin.NewClient(id, *onet.NewRoster([]*network.ServerIdentity{si}))
				cc, err = cl.GetChainConfig()
				if err != nil {
					cl = nil
					continue
				}
				cl.Roster = cc.Roster
				break
			}
		}
		if cl == nil {
			return errors.New("didn't manage to find a node with a valid copy of the given skipchain-id")
		}
		ad := &darc.Darc{}
		adPub := cothority.Suite.Point()
		// Accept both plain-darcs, as well as "darc:...." darcs
		adID, err := stringToDarcID(c.String("admindarc"))
		if err == nil {
			adPubBuf, err := stringToEd25519Buf(c.String("adminpub"))
			if err != nil {
				return err
			}
			adPub = cothority.Suite.Point()
			if err = adPub.UnmarshalBinary(adPubBuf); err != nil {
				return errors.New("got an invalid admin public key: " + err.Error())
			}
			p, err := cl.GetProof(adID)
			if err != nil {
				return errors.New("couldn't get proof for admin-darc: " + err.Error())
			}
			if err = p.Proof.Verify(id); err != nil {
				return errors.New("proof for admin is wrong: " + err.Error())
			}
			_, adBuf, cid, _, err := p.Proof.KeyValue()
			if err != nil {
				return errors.New("cannot get value for darc: " + err.Error())
			}
			if cid != byzcoin.ContractDarcID {
				return errors.New("please give a darc-instance ID, not: " + cid)
			}
			ad, err = darc.NewFromProtobuf(adBuf)
			if err != nil {
				return errors.New("invalid darc stored in byzcoin: " + err.Error())
			}
		}
		log.Infof("ByzCoin-config for %+x:\n"+
			"\tRoster: %s\n"+
			"\tBlockInterval: %s\n"+
			"\tMacBlockSize: %d\n"+
			"\tDarcContracts: %s",
			id[:], cc.Roster.List, cc.BlockInterval, cc.MaxBlockSize, cc.DarcContractIDs)
		fn, err := lib.SaveConfig(lib.Config{
			Roster:        cc.Roster,
			ByzCoinID:     id,
			AdminDarc:     *ad,
			AdminIdentity: darc.NewIdentityEd25519(adPub),
		})
		if err != nil {
			return errors.New("while writing config-file: " + err.Error())
		}
		log.Info("Wrote config to", path.Join(lib.ConfigPath, fn))
	}
	return nil
}

func latest(c *cli.Context) error {
	bcArg := c.String("bc")
	if bcArg == "" {
		bcArg = c.Args().First()
		if bcArg == "" {
			return errors.New("--bc flag is required")
		}
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	// Allow the user to set the server number; useful when testing leader rotation.
	cl.ServerNumber = c.Int("server")
	if cl.ServerNumber > len(cl.Roster.List)-1 {
		return errors.New("server index out of range")
	}

	_, err = fmt.Fprintf(c.App.Writer, "ByzCoinID: %x\n", cfg.ByzCoinID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.App.Writer, "Admin DARC: %x\n", cfg.AdminDarc.GetBaseID())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.App.Writer, "local roster:", fmtRoster(&cfg.Roster))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.App.Writer, "contacting server:", cl.Roster.List[cl.ServerNumber])
	if err != nil {
		return err
	}

	// Find the latest block by asking for the Proof of the config instance.
	p, err := cl.GetProof(byzcoin.ConfigInstanceID.Slice())
	if err != nil {
		return err
	}

	err = p.Proof.Verify(cfg.ByzCoinID)
	if err != nil {
		return err
	}

	sb := p.Proof.Latest
	_, err = fmt.Fprintf(c.App.Writer, "Last block:\n\tIndex: %d\n\tBlockMaxHeight: %d\n\tBackLinks: %d\n\tRoster: %s\n\n",
		sb.Index, sb.Height, len(sb.BackLinkIDs), fmtRoster(sb.Roster))
	if err != nil {
		return err
	}

	if c.Bool("update") {
		cfg.Roster = *sb.Roster
		var fn string
		fn, err = lib.SaveConfig(cfg)
		if err == nil {
			_, err = fmt.Fprintln(c.App.Writer, "updated config file:", fn)
			if err != nil {
				return err
			}
		}
	}

	return err
}

func fmtRoster(r *onet.Roster) string {
	var roster []string
	for _, s := range r.List {
		if s.URL != "" {
			roster = append(roster, fmt.Sprintf("%v (url: %v)", string(s.Address), s.URL))
		} else {
			roster = append(roster, string(s.Address))
		}
	}
	return strings.Join(roster, ", ")
}

func getBcKey(c *cli.Context) (cfg lib.Config, cl *byzcoin.Client, signer *darc.Signer,
	proof byzcoin.Proof, chainCfg byzcoin.ChainConfig, err error) {
	if c.NArg() < 2 {
		err = errors.New("please give the following arguments: bc-xxx.cfg key-xxx.cfg")
		return
	}
	cfg, cl, err = lib.LoadConfig(c.Args().First())
	if err != nil {
		err = errors.New("couldn't load config file: " + err.Error())
		return
	}
	signer, err = lib.LoadSigner(c.Args().Get(1))
	if err != nil {
		err = errors.New("couldn't load key-xxx.cfg: " + err.Error())
		return
	}

	log.Lvl2("Getting latest chainConfig")
	pr, err := cl.GetProof(byzcoin.ConfigInstanceID.Slice())
	if err != nil {
		err = errors.New("couldn't get proof for chainConfig: " + err.Error())
		return
	}
	proof = pr.Proof

	_, value, _, _, err := proof.KeyValue()
	if err != nil {
		err = errors.New("couldn't get value out of proof: " + err.Error())
		return
	}
	err = protobuf.DecodeWithConstructors(value, &chainCfg, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		err = errors.New("couldn't decode chainConfig: " + err.Error())
		return
	}
	return
}

func getBcKeyPub(c *cli.Context) (cfg lib.Config, cl *byzcoin.Client, signer *darc.Signer,
	proof byzcoin.Proof, chainCfg byzcoin.ChainConfig, pub *network.ServerIdentity, err error) {
	cfg, cl, signer, proof, chainCfg, err = getBcKey(c)
	if err != nil {
		return
	}

	fn := c.Args().Get(2)
	if fn == "" {
		err = errors.New("no TOML file provided")
		return
	}
	f, err := os.Open(fn)
	if err != nil {
		return
	}
	defer f.Close()
	group, err := app.ReadGroupDescToml(f)
	if err != nil {
		err = fmt.Errorf("couldn't open %v: %v", fn, err.Error())
		return
	}
	if len(group.Roster.List) != 1 {
		err = errors.New("the TOML file should have exactly one entry")
		return
	}
	pub = group.Roster.List[0]

	return
}

func updateConfig(cl *byzcoin.Client, signer *darc.Signer, chainConfig byzcoin.ChainConfig) error {
	counters, err := cl.GetSignerCounters(signer.Identity().String())
	if err != nil {
		return errors.New("couldn't get counters: " + err.Error())
	}
	counters.Counters[0]++
	ccBuf, err := protobuf.Encode(&chainConfig)
	if err != nil {
		return errors.New("couldn't encode chainConfig: " + err.Error())
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: byzcoin.Instructions{{
			InstanceID: byzcoin.ConfigInstanceID,
			Invoke: &byzcoin.Invoke{
				ContractID: byzcoin.ContractConfigID,
				Command:    "update_config",
				Args:       byzcoin.Arguments{{Name: "config", Value: ccBuf}},
			},
			SignerCounter: counters.Counters,
		}},
	}

	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return errors.New("couldn't sign the clientTransaction: " + err.Error())
	}

	log.Lvl1("Sending new roster to byzcoin")
	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return errors.New("client transaction wasn't accepted: " + err.Error())
	}
	return nil
}

func config(c *cli.Context) error {
	_, cl, signer, _, chainConfig, err := getBcKey(c)
	if err != nil {
		return err
	}

	if interval := c.String("interval"); interval != "" {
		dur, err := time.ParseDuration(interval)
		if err != nil {
			return errors.New("couldn't parse interval: " + err.Error())
		}
		chainConfig.BlockInterval = dur
	}
	if blockSize := c.Int("blockSize"); blockSize > 0 {
		if blockSize < 16000 && blockSize > 8e6 {
			return errors.New("new blocksize out of bounds: must be between 16e3 and 8e6")
		}
		chainConfig.MaxBlockSize = blockSize
	}

	err = updateConfig(cl, signer, chainConfig)
	if err != nil {
		return err
	}

	log.Lvl1("Updated configuration")

	return nil
}

func mint(c *cli.Context) error {
	if c.NArg() < 4 {
		return errors.New("please give the following arguments: bc-xxx.cfg key-xxx.cfg pubkey coins")
	}
	cfg, cl, signer, _, _, err := getBcKey(c)
	if err != nil {
		return err
	}

	pubBuf, err := hex.DecodeString(c.Args().Get(2))
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write([]byte(contracts.ContractCoinID))
	h.Write(pubBuf)
	account := byzcoin.NewInstanceID(h.Sum(nil))

	coins, err := strconv.ParseUint(c.Args().Get(3), 10, 64)
	if err != nil {
		return err
	}
	coinsBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(coinsBuf, coins)

	cReply, err := cl.GetSignerCounters(signer.Identity().String())
	if err != nil {
		return err
	}
	counters := cReply.Counters

	p, err := cl.GetProof(account.Slice())
	if err != nil {
		return err
	}
	if !p.Proof.InclusionProof.Match(account.Slice()) {
		log.Info("Creating darc and coin")
		pub := cothority.Suite.Point()
		err = pub.UnmarshalBinary(pubBuf)
		if err != nil {
			return err
		}
		pubI := darc.NewIdentityEd25519(pub)
		rules := darc.NewRules()
		err = rules.AddRule(darc.Action("spawn:coin"), expression.Expr(signer.Identity().String()))
		if err != nil {
			return err
		}
		err = rules.AddRule(darc.Action("invoke:coin.transfer"), expression.Expr(pubI.String()))
		if err != nil {
			return err
		}
		err = rules.AddRule(darc.Action("invoke:coin.mint"), expression.Expr(signer.Identity().String()))
		if err != nil {
			return err
		}
		d := darc.NewDarc(rules, []byte("new coin for mba"))
		dBuf, err := d.ToProto()
		if err != nil {
			return err
		}

		log.Info("Creating darc for coin")
		counters[0]++
		ctx := byzcoin.ClientTransaction{
			Instructions: byzcoin.Instructions{{
				InstanceID: byzcoin.NewInstanceID(cfg.AdminDarc.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: byzcoin.ContractDarcID,
					Args: byzcoin.Arguments{{
						Name:  "darc",
						Value: dBuf,
					}},
				},
				SignerCounter: counters,
			}},
		}
		err = ctx.FillSignersAndSignWith(*signer)
		if err != nil {
			return err
		}
		_, err = cl.AddTransactionAndWait(ctx, 10)
		if err != nil {
			return err
		}

		log.Info("Creating coin")
		counters[0]++
		ctx = byzcoin.ClientTransaction{
			Instructions: byzcoin.Instructions{{
				InstanceID: byzcoin.NewInstanceID(d.GetBaseID()),
				Spawn: &byzcoin.Spawn{
					ContractID: contracts.ContractCoinID,
					Args: byzcoin.Arguments{
						{
							Name:  "type",
							Value: contracts.CoinName.Slice(),
						},
						{
							Name:  "coinID",
							Value: pubBuf,
						},
					},
				},
				SignerCounter: counters,
			}},
		}
		err = ctx.FillSignersAndSignWith(*signer)
		if err != nil {
			return err
		}
		_, err = cl.AddTransactionAndWait(ctx, 10)
		if err != nil {
			return err
		}
	}

	log.Info("Minting coin")
	counters[0]++
	ctx := byzcoin.ClientTransaction{
		Instructions: byzcoin.Instructions{{
			InstanceID: account,
			Invoke: &byzcoin.Invoke{
				ContractID: contracts.ContractCoinID,
				Command:    "mint",
				Args: byzcoin.Arguments{{
					Name:  "coins",
					Value: coinsBuf,
				}},
			},
			SignerCounter: counters,
		}},
	}
	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return err
	}
	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return err
	}

	log.Infof("Account %x created and filled with %d coins", account[:], coins)
	return nil
}

func rosterAdd(c *cli.Context) error {
	if c.NArg() < 3 {
		return errors.New("please give the following arguments: bc-xxx.cfg key-xxx.cfg newServer.toml")
	}
	_, cl, signer, _, chainConfig, pub, err := getBcKeyPub(c)
	if err != nil {
		return err
	}

	old := chainConfig.Roster
	if i, _ := old.Search(pub.ID); i >= 0 {
		return errors.New("new node is already in roster")
	}
	log.Lvl2("Old roster is:", old.List)
	chainConfig.Roster = *old.Concat(pub)
	log.Lvl2("New roster is:", chainConfig.Roster.List)

	err = updateConfig(cl, signer, chainConfig)
	if err != nil {
		return err
	}
	log.Lvl1("New roster is now active")
	return nil
}

func rosterDel(c *cli.Context) error {
	if c.NArg() < 3 {
		return errors.New("please give the following arguments: bc-xxx.cfg key-xxx.cfg serverToDelete.toml")
	}
	_, cl, signer, _, chainConfig, pub, err := getBcKeyPub(c)
	if err != nil {
		return err
	}

	old := chainConfig.Roster
	i, _ := old.Search(pub.ID)
	switch {
	case i < 0:
		return errors.New("node to delete is not in roster")
	case i == 0:
		return errors.New("cannot delete leader from roster")
	}
	log.Lvl2("Old roster is:", old.List)
	list := append(old.List[0:i], old.List[i+1:]...)
	chainConfig.Roster = *onet.NewRoster(list)
	log.Lvl2("New roster is:", chainConfig.Roster.List)

	err = updateConfig(cl, signer, chainConfig)
	if err != nil {
		return err
	}
	log.Lvl1("New roster is now active")
	return nil
}

func rosterLeader(c *cli.Context) error {
	if c.NArg() < 3 {
		return errors.New("please give the following arguments: bc-xxx.cfg key-xxx.cfg newLeader.toml")
	}
	_, cl, signer, _, chainConfig, pub, err := getBcKeyPub(c)
	if err != nil {
		return err
	}

	old := chainConfig.Roster
	i, _ := old.Search(pub.ID)
	switch {
	case i < 0:
		return errors.New("new leader is not in roster")
	case i == 0:
		return errors.New("new node is already leader")
	}
	log.Lvl2("Old roster is:", old.List)
	list := []*network.ServerIdentity(old.List)
	list[0], list[i] = list[i], list[0]
	chainConfig.Roster = *onet.NewRoster(list)
	log.Lvl2("New roster is:", chainConfig.Roster.List)

	// Do it twice to make sure the new roster is active - there is an issue ;)
	err = updateConfig(cl, signer, chainConfig)
	if err != nil {
		return err
	}
	err = updateConfig(cl, signer, chainConfig)
	if err != nil {
		return err
	}
	log.Lvl1("New roster is now active")
	return nil
}

func key(c *cli.Context) error {
	if f := c.String("print"); f != "" {
		sig, err := lib.LoadSigner(f)
		if err != nil {
			return errors.New("couldn't load signer: " + err.Error())
		}
		log.Infof("Private: %s\nPublic: %s", sig.Ed25519.Secret, sig.Ed25519.Point)
		//log.Infof("Private: 65642e706f696e74%s\nPublic: %s", sig.Ed25519.Secret, sig.Ed25519.Point)
		return nil
	}
	newSigner := darc.NewSignerEd25519(nil, nil)
	err := lib.SaveKey(newSigner)
	if err != nil {
		return err
	}

	var fo io.Writer

	save := c.String("save")
	if save == "" {
		fo = os.Stdout
	} else {
		file, err := os.Create(save)
		if err != nil {
			return err
		}
		fo = file
		defer func() {
			err := file.Close()
			if err != nil {
				log.Error(err)
			}
		}()
	}
	_, err = fmt.Fprintln(fo, newSigner.Identity().String())
	return err
}

func darcShow(c *cli.Context) error {
	bcArg := c.String("bc")
	if bcArg == "" {
		return errors.New("--bc flag is required")
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	dstr := c.String("darc")
	if dstr == "" {
		dstr = cfg.AdminDarc.GetIdentityString()
	}

	d, err := getDarcByString(cl, dstr)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.App.Writer, d.String())
	return err
}

func debugReplay(c *cli.Context) error {
	if c.NArg() < 1 {
		return errors.New("please give the following arguments: url [bcID]")
	}
	if c.NArg() == 1 {
		return debugList(c)
	}

	r := &onet.Roster{List: []*network.ServerIdentity{{URL: c.Args().First()}}}
	if r == nil {
		return errors.New("couldn't create roster")
	}
	bcID, err := hex.DecodeString(c.Args().Get(1))
	if err != nil {
		return err
	}

	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()
	servers := local.GenServers(1)
	s := servers[0].Service(byzcoin.ServiceName).(*byzcoin.Service)

	cl := skipchain.NewClient()
	var sst *byzcoin.StagingStateTrie
	sb, err := cl.GetSingleBlock(r, bcID)
	if err != nil {
		return err
	}
	for {
		if sb.Payload != nil {
			var dBody byzcoin.DataBody
			err := protobuf.Decode(sb.Payload, &dBody)
			if err != nil {
				return err
			}
			var dHead byzcoin.DataHeader
			err = protobuf.Decode(sb.Data, &dHead)
			if err != nil {
				return err
			}
			log.Infof("Block %d has %d transactions and was created at %s", sb.Index, len(dBody.TxResults),
				time.Unix(dHead.Timestamp/1e9, 0))

			if bytes.Compare(dHead.ClientTransactionHash, dBody.TxResults.Hash()) != 0 {
				return errors.New("client transaction has does not match")
			}

			if sb.Index == 0 {
				log.Lvl1("Creating stateTrie")
				nonce, err := s.LoadNonceFromTxs(dBody.TxResults)
				if err != nil {
					return err
				}
				sst, err = byzcoin.NewMemStagingStateTrie(nonce)
				if err != nil {
					return err
				}
			}
			for _, tx := range dBody.TxResults {
				for i, inst := range tx.ClientTransaction.Instructions {
					log.Lvlf1("Accepted: %t - Index: %d\n%s", tx.Accepted, i, inst)
				}
				if tx.Accepted {
					var sc byzcoin.StateChanges
					sc, sst, err = s.ProcessOneTx(sst, tx.ClientTransaction)
					if err != nil {
						return err
					}
					log.Lvlf3("Got %d statechanges.", len(sc))
				}
			}

			if bytes.Compare(dHead.TrieRoot, sst.GetRoot()) != 0 {
				return errors.New("merkle tree root doesn't match with trie root")
			}
		} else {
			log.Infof("Block %d has no payload", sb.Index)
		}
		if len(sb.ForwardLink) == 0 {
			break
		}
		sb, err = cl.GetSingleBlock(r, sb.ForwardLink[0].To)
		if err != nil {
			return err
		}
	}
	return nil
}

func debugList(c *cli.Context) error {
	if c.NArg() < 1 {
		return errors.New("please give (ip:port | group.toml) as argument")
	}

	var urls []string
	if f, err := os.Open(c.Args().First()); err == nil {
		defer f.Close()
		group, err := app.ReadGroupDescToml(f)
		if err != nil {
			return err
		}
		for _, si := range group.Roster.List {
			if si.URL != "" {
				urls = append(urls, si.URL)
			} else {
				p, err := strconv.Atoi(si.Address.Port())
				if err != nil {
					return err
				}
				urls = append(urls, fmt.Sprintf("http://%s:%d", si.Address.Host(), p+1))
			}
		}
	} else {
		urls = []string{c.Args().First()}
	}

	for _, url := range urls {
		log.Info("Contacting ", url)
		resp, err := byzcoin.Debug(url, nil)
		if err != nil {
			log.Error(err)
			continue
		}
		sort.SliceStable(resp.Byzcoins, func(i, j int) bool {
			var iData byzcoin.DataHeader
			var jData byzcoin.DataHeader
			err := protobuf.Decode(resp.Byzcoins[i].Genesis.Data, &iData)
			if err != nil {
				return false
			}
			err = protobuf.Decode(resp.Byzcoins[j].Genesis.Data, &jData)
			if err != nil {
				return false
			}
			return iData.Timestamp > jData.Timestamp
		})
		for _, rb := range resp.Byzcoins {
			log.Infof("ByzCoinID %x has", rb.ByzCoinID)
			headerGenesis := byzcoin.DataHeader{}
			headerLatest := byzcoin.DataHeader{}
			err := protobuf.Decode(rb.Genesis.Data, &headerGenesis)
			if err != nil {
				log.Error(err)
				continue
			}
			err = protobuf.Decode(rb.Latest.Data, &headerLatest)
			if err != nil {
				log.Error(err)
				continue
			}
			log.Infof("\tBlocks: %d\n\tFrom %s to %s\tBlock hash: %x",
				rb.Latest.Index,
				time.Unix(headerGenesis.Timestamp/1e9, 0),
				time.Unix(headerLatest.Timestamp/1e9, 0),
				rb.Latest.Hash[:])
			if c.Bool("verbose") {
				log.Infof("\tGenesis block header: %+v\n\tLatest block header: %+v",
					rb.Genesis.SkipBlockFix,
					rb.Latest.SkipBlockFix)
			}
			log.Info()
		}
	}
	return nil
}

func debugDump(c *cli.Context) error {
	if c.NArg() < 2 {
		return errors.New("please give the following arguments: ip:port byzcoin-id")
	}

	bcidBuf, err := hex.DecodeString(c.Args().Get(1))
	if err != nil {
		log.Error(err)
		return err
	}
	bcid := skipchain.SkipBlockID(bcidBuf)
	resp, err := byzcoin.Debug(c.Args().First(), &bcid)
	if err != nil {
		log.Error(err)
		return err
	}
	sort.SliceStable(resp.Dump, func(i, j int) bool {
		return bytes.Compare(resp.Dump[i].Key, resp.Dump[j].Key) < 0
	})
	for _, inst := range resp.Dump {
		log.Infof("%x / %d: %s", inst.Key, inst.State.Version, string(inst.State.ContractID))
		if c.Bool("verbose") {
			switch inst.State.ContractID {
			case byzcoin.ContractDarcID:
				d, err := darc.NewFromProtobuf(inst.State.Value)
				if err != nil {
					log.Warn("Didn't recognize as a darc instance")
				}
				log.Infof("\tDesc: %s, Rules:", string(d.Description))
				for _, r := range d.Rules.List {
					log.Infof("\tAction: %s - Expression: %s", r.Action, r.Expr)
				}
			}
		}
	}

	return nil
}

func debugRemove(c *cli.Context) error {
	if c.NArg() < 2 {
		return errors.New("please give the following arguments: private.toml byzcoin-id")
	}

	ccfg, err := app.LoadCothority(c.Args().First())
	if err != nil {
		return err
	}
	si, err := ccfg.GetServerIdentity()
	if err != nil {
		return err
	}
	bcidBuf, err := hex.DecodeString(c.Args().Get(1))
	if err != nil {
		log.Error(err)
		return err
	}
	bcid := skipchain.SkipBlockID(bcidBuf)
	err = byzcoin.DebugRemove(si, bcid)
	if err != nil {
		return err
	}
	log.Infof("Successfully removed ByzCoinID %x from %s", bcid, si.Address)
	return nil
}

func darcAdd(c *cli.Context) error {
	bcArg := c.String("bc")
	if bcArg == "" {
		return errors.New("--bc flag is required")
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	dstr := c.String("darc")
	if dstr == "" {
		dstr = cfg.AdminDarc.GetIdentityString()
	}
	dSpawn, err := getDarcByString(cl, dstr)
	if err != nil {
		return err
	}

	var signer *darc.Signer

	sstr := c.String("sign")
	if sstr == "" {
		signer, err = lib.LoadKey(cfg.AdminIdentity)
	} else {
		signer, err = lib.LoadKeyFromString(sstr)
	}
	if err != nil {
		return err
	}

	var identity darc.Identity
	var newSigner *darc.Signer

	owner := c.String("owner")
	if owner != "" {
		identity, err = darc.ParseIdentity(owner)
		if err != nil {
			return err
		}
	} else {
		s := darc.NewSignerEd25519(nil, nil)
		err = lib.SaveKey(s)
		if err != nil {
			return err
		}
		identity = s.Identity()
		newSigner = &s
	}

	var desc []byte
	if c.String("desc") == "" {
		desc = random.Bits(32, true, random.New())
	} else {
		if len(c.String("desc")) > 1024 {
			return errors.New("descriptions longer than 1024 characters are not allowed")
		}
		desc = []byte(c.String("desc"))
	}

	rules := darc.InitRulesWith([]darc.Identity{identity}, []darc.Identity{identity}, "invoke:"+byzcoin.ContractDarcID+".evolve")
	if c.Bool("unrestricted") {
		err = rules.AddRule("invoke:"+byzcoin.ContractDarcID+".evolve_unrestricted", expression.Expr(identity.String()))
		if err != nil {
			return err
		}
	}
	d := darc.NewDarc(rules, desc)

	dBuf, err := d.ToProto()
	if err != nil {
		return err
	}

	instID := byzcoin.NewInstanceID(dSpawn.GetBaseID())

	counters, err := cl.GetSignerCounters(signer.Identity().String())

	spawn := byzcoin.Spawn{
		ContractID: byzcoin.ContractDarcID,
		Args: []byzcoin.Argument{
			{
				Name:  "darc",
				Value: dBuf,
			},
		},
	}

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			{
				InstanceID:    instID,
				Spawn:         &spawn,
				SignerCounter: []uint64{counters.Counters[0] + 1},
			},
		},
	}
	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return err
	}

	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(c.App.Writer, d.String())
	if err != nil {
		return err
	}

	// Saving ID in special file
	output := c.String("out_id")
	if output != "" {
		err = ioutil.WriteFile(output, []byte(d.GetIdentityString()), 0644)
		if err != nil {
			return err
		}
	}

	// Saving key in special file
	output = c.String("out_key")
	if newSigner != nil && output != "" {
		err = ioutil.WriteFile(output, []byte(newSigner.Identity().String()), 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func darcRule(c *cli.Context) error {
	bcArg := c.String("bc")
	if bcArg == "" {
		return errors.New("--bc flag is required")
	}

	cfg, cl, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	dstr := c.String("darc")
	if dstr == "" {
		dstr = cfg.AdminDarc.GetIdentityString()
	}
	d, err := getDarcByString(cl, dstr)
	if err != nil {
		return err
	}

	var signer *darc.Signer

	sstr := c.String("sign")
	if sstr == "" {
		signer, err = lib.LoadKey(cfg.AdminIdentity)
	} else {
		signer, err = lib.LoadKeyFromString(sstr)
	}
	if err != nil {
		return err
	}

	action := c.String("rule")
	if action == "" {
		return errors.New("--rule flag is required")
	}

	identity := c.String("identity")
	if identity == "" {
		if !c.Bool("delete") {
			return errors.New("--identity flag is required")
		}
	}

	d2 := d.Copy()
	err = d2.EvolveFrom(d)
	if err != nil {
		return err
	}

	switch {
	case c.Bool("delete"):
		err = d2.Rules.DeleteRules(darc.Action(action))
	case c.Bool("replace"):
		err = d2.Rules.UpdateRule(darc.Action(action), []byte(identity))
	default:
		err = d2.Rules.AddRule(darc.Action(action), []byte(identity))
	}

	if err != nil {
		return err
	}

	d2Buf, err := d2.ToProto()
	if err != nil {
		return err
	}

	counters, err := cl.GetSignerCounters(signer.Identity().String())

	invoke := byzcoin.Invoke{
		ContractID: byzcoin.ContractDarcID,
		Command:    "evolve_unrestricted",
		Args: []byzcoin.Argument{
			{
				Name:  "darc",
				Value: d2Buf,
			},
		},
	}

	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{
			{
				InstanceID:    byzcoin.NewInstanceID(d2.GetBaseID()),
				Invoke:        &invoke,
				SignerCounter: []uint64{counters.Counters[0] + 1},
			},
		},
	}
	err = ctx.FillSignersAndSignWith(*signer)
	if err != nil {
		return err
	}

	_, err = cl.AddTransactionAndWait(ctx, 10)
	if err != nil {
		return err
	}

	return nil
}

func qrcode(c *cli.Context) error {
	type pair struct {
		Priv string
		Pub  string
	}
	type baseconfig struct {
		ByzCoinID skipchain.SkipBlockID
	}

	type adminconfig struct {
		ByzCoinID skipchain.SkipBlockID
		Admin     pair
	}

	bcArg := c.String("bc")
	if bcArg == "" {
		return errors.New("--bc flag is required")
	}

	cfg, _, err := lib.LoadConfig(bcArg)
	if err != nil {
		return err
	}

	var toWrite []byte

	if c.Bool("admin") {
		signer, err := lib.LoadKey(cfg.AdminIdentity)
		if err != nil {
			return err
		}

		priv, err := signer.GetPrivate()
		if err != nil {
			return err
		}

		toWrite, err = json.Marshal(adminconfig{
			ByzCoinID: cfg.ByzCoinID,
			Admin: pair{
				Priv: priv.String(),
				Pub:  signer.Identity().String(),
			},
		})
	} else {
		toWrite, err = json.Marshal(baseconfig{
			ByzCoinID: cfg.ByzCoinID,
		})
	}

	if err != nil {
		return err
	}

	qr, err := qrgo.NewQR(string(toWrite))
	if err != nil {
		return err
	}

	qr.OutputTerminal()

	return nil
}

type configPrivate struct {
	Owner darc.Signer
}

func init() { network.RegisterMessages(&configPrivate{}) }

func stringToDarcID(id string) ([]byte, error) {
	if id == "" {
		return nil, errors.New("no string given")
	}
	if strings.HasPrefix(id, "darc:") {
		id = id[5:]
	}
	return hex.DecodeString(id)
}

func stringToEd25519Buf(pub string) ([]byte, error) {
	if pub == "" {
		return nil, errors.New("no string given")
	}
	if strings.HasPrefix(pub, "ed25519:") {
		pub = pub[8:]
	}
	return hex.DecodeString(pub)
}

func getDarcByString(cl *byzcoin.Client, id string) (*darc.Darc, error) {
	xrep, err := stringToDarcID(id)
	if err != nil {
		return nil, err
	}
	return getDarcByID(cl, xrep)
}

func getDarcByID(cl *byzcoin.Client, id []byte) (*darc.Darc, error) {
	pr, err := cl.GetProof(id)
	if err != nil {
		return nil, err
	}

	p := &pr.Proof
	err = p.Verify(cl.ID)
	if err != nil {
		return nil, err
	}

	vs, cid, _, err := p.Get(id)
	if err != nil {
		return nil, fmt.Errorf("could not find darc for %x", id)
	}
	if cid != byzcoin.ContractDarcID {
		return nil, fmt.Errorf("unexpected contract %v, expected a darc", cid)
	}

	d, err := darc.NewFromProtobuf(vs)
	if err != nil {
		return nil, err
	}

	return d, nil
}

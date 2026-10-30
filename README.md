# swarma-keyvault

Key custody for swarma agents: non-extractable keys held by a dedicated holder, used by agents only through narrow,
audited operations, never handed out. The project starts from the existing `mac-keyvault` in relux-works/mac-infra
(P-256 keys in the login keychain, the service KEK broker and its `kekclient`) and carries it, with a skill for
working with it, into a standalone swarm component.

Status: preparation. Nothing is moved yet. The plan and its design come first, then the extraction once the current
keyvault work in mac-infra is finished.

Owner direction, 2026-10-30: «давай когда по макинфре киволт допилится мы зарядим сварма киволт или чот такое проект в
сварме посадим туда орка ипусть кипер киволта из макинфры передаст ему киволт чтоб тот уже в свою очередь позырил в
книгу свармы и взял наш киволт и аккуратно обосбил его в наш новыйхпроект со скилом работы с ним», and «подготовительные
работы уже мож сделать и засадить орка».

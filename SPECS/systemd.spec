%global package_speccommit c45860427a630d54a29c54b18ecfa252a156a3db
%global usver 219
%global xsver 57.5
%global xsrel %{xsver}%{?xscount}%{?xshash}
%global package_srccommit v219

# We ship a .pc file but don't want to have a dep on pkg-config. We
# strip the automatically generated dep here and instead co-own the
# directory.
%global __requires_exclude pkg-config
%global _hardened_build 1

Name:           systemd
Url:            http://www.freedesktop.org/wiki/Software/systemd
Version:        219
Release:        %{?xsrel}%{?dist}
# For a breakdown of the licensing, see README
License:        LGPLv2+ and MIT and GPLv2+
Summary:        A System and Service Manager

Source0: systemd-219.tar.gz
Patch0: 0001-kernel-install-add-fedora-specific-callouts-to-new-k.patch
Patch1: 0002-Revert-fsck-re-enable-fsck-l.patch
Patch2: 0003-sysctl-bring-back-etc-sysctl.conf.patch
Patch3: 0004-remove-user-.service.patch
Patch4: 0005-logind-session-save-stopping-flag.patch
Patch5: 0006-man-mention-System-Administrator-s-Guide-in-systemct.patch
Patch6: 0007-rules-automatically-online-hot-added-CPUs.patch
Patch7: 0008-Revert-remove-references-of-readahead.patch
Patch8: 0009-Revert-missing-remove-fanotify.patch
Patch9: 0010-Revert-readahead-wipe-out-readahead.patch
Patch10: 0011-rules-add-rule-for-naming-Dell-iDRAC-USB-Virtual-NIC.patch
Patch11: 0012-udev-net_id-correctly-name-netdevs-based-on-dev_port.patch
Patch12: 0013-Revert-blkid-Warn-when-rejecting-a-superblock-with-a.patch
Patch13: 0014-journald-audit-exit-gracefully-in-the-case-we-can-t-.patch
Patch14: 0015-fedora-disable-resolv.conf-symlink.patch
Patch15: 0016-Revert-timedated-manage-systemd-timesyncd-directly-i.patch
Patch16: 0017-journal-remote-fix-certificate-status-memory-leak.patch
Patch17: 0018-journal-remote-fix-client_cert-memory-leak.patch
Patch18: 0019-tmpfiles-Fix-parse_acl-error-message.patch
Patch19: 0020-test-utf8-fix-utf16-tests-on-BE-machines.patch
Patch20: 0021-tmpfiles-avoid-creating-duplicate-acl-entries.patch
Patch21: 0022-shared-time-util-fix-gcc5-warning.patch
Patch22: 0023-test-time-test-infinity-parsing-in-nanoseconds.patch
Patch23: 0024-bootchart-fix-default-init-path.patch
Patch24: 0025-systemctl-bump-NOFILE-only-for-systemctl_main.patch
Patch25: 0026-acl-util-avoid-freeing-uninitialized-pointer.patch
Patch26: 0027-bootchart-svg-fix-checking-of-list-end.patch
Patch27: 0028-systemd-add-getrandom-syscall-numbers-for-MIPS.patch
Patch28: 0029-unit-use-weaker-dependencies-between-mount-and-devic.patch
Patch29: 0030-unit-When-stopping-due-to-BindsTo-log-which-unit-cau.patch
Patch30: 0031-sysctl-downgrade-message-about-sysctl-overrides-to-d.patch
Patch31: 0032-sysctl-add-some-hints-how-to-override-settings.patch
Patch32: 0033-core-rework-device-state-logic.patch
Patch33: 0034-core-fix-return-value-on-OOM.patch
Patch34: 0035-machined-use-x-machine-unix-prefix-for-the-container.patch
Patch35: 0036-shared-AFS-is-also-a-network-filesystem.patch
Patch36: 0037-core-downgrade-unit-type-not-supported-message.patch
Patch37: 0038-journal-remote-fix-saving-of-binary-fields.patch
Patch38: 0039-journal-fix-Inappropriate-ioctl-for-device-on-ext4.patch
Patch39: 0040-sd-daemon-replace-VLA-with-alloca-to-make-llvm-happy.patch
Patch40: 0041-tmpfiles-quietly-ignore-ACLs-on-unsupported-filesyst.patch
Patch41: 0042-shared-util-assume-ac-when-sys-class-power_supply-is.patch
Patch42: 0043-import-remove-unused-variable.patch
Patch43: 0044-hwdb-fix-ThinkPad-X-Tablet-special-keys.patch
Patch44: 0045-man-add-newlines-to-the-pull-raw-example-in-machinec.patch
Patch45: 0046-core-shared-in-deserializing-match-same-files-reache.patch
Patch46: 0047-shared-use-SocketAddress-in-socket_address_matches_f.patch
Patch47: 0048-shared-avoid-semi-duplicating-socket_address_equal.patch
Patch48: 0049-shared-handle-unnamed-sockets-in-socket_address_equa.patch
Patch49: 0050-man-make-bootup-graph-consistent.patch
Patch50: 0051-nspawn-fix-whitespace-and-typo-in-partition-table-bl.patch
Patch51: 0052-man-explain-time-units-in-tmpfiles.patch
Patch52: 0053-systemctl-check-validity-of-PID-we-received.patch
Patch53: 0054-systemctl-support-auditd.service-better.patch
Patch54: 0055-shared-unit-name-fix-gcc5-warning.patch
Patch55: 0056-test-hashmap-fix-gcc5-warning.patch
Patch56: 0057-shared-fix-wrong-assertion-in-barrier_set_role.patch
Patch57: 0058-hwdb-Update-database-of-Bluetooth-company-identifier.patch
Patch58: 0059-journal-make-skipping-of-exhausted-journal-files-eff.patch
Patch59: 0060-shared-condition-fix-gcc5-warning.patch
Patch60: 0061-man-correct-description-of-systemd-user-sessions.patch
Patch61: 0062-build-sys-allow-lto-and-FORTIFY_SOURCE-with-O-sz.patch
Patch62: 0063-man-fix-typo.patch
Patch63: 0064-bus-proxyd-avoid-logging-oom-twice.patch
Patch64: 0065-Do-not-run-sysv-generator-test-when-sysv-compat-is-d.patch
Patch65: 0066-README-mention-ACLs-more.patch
Patch66: 0067-Do-not-advertise-.d-snippets-over-main-config-file.patch
Patch67: 0068-hwdb-add-pnpid-for-the-T450s-touchpad.patch
Patch68: 0069-networkd-netdev-inform-when-we-take-over-an-existing.patch
Patch69: 0070-man-replace-obsolete-wiki-link-with-man-page.patch
Patch70: 0071-Use-correct-uname-identifiers-in-arch_map-for-SuperH.patch
Patch71: 0072-hwdb-fix-Dell-XPS12-9Q33-key-name.patch
Patch72: 0073-Remove-the-cap-on-epoll-events.patch
Patch73: 0074-Allow-up-to-4096-simultaneous-connections.patch
Patch74: 0075-hwdb-add-Logitech-G5-Laser-Mouse.patch
Patch75: 0076-tmpfiles-Fix-handling-of-duplicate-lines.patch
Patch76: 0077-hwdb-add-Lenovo-W451-to-TOUCHPAD_HAS_TRACKPOINT_BUTT.patch
Patch77: 0078-vconsole-match-on-vtcon-events-not-fbcon-ones.patch
Patch78: 0079-core-do-not-spawn-jobs-or-touch-other-units-during-c.patch
Patch79: 0080-firstboot-set-all-spwd-fields-to-1-for-consistency-w.patch
Patch80: 0081-sysusers-do-not-reject-users-with-already-present-et.patch
Patch81: 0082-nspawn-fix-use-after-free-and-leak-in-error-paths.patch
Patch82: 0083-login-fix-copy-pasto-in-error-path.patch
Patch83: 0084-journalctl-update-hint-now-that-we-set-ACL-everywher.patch
Patch84: 0085-sd-journal-return-error-when-we-cannot-open-a-file.patch
Patch85: 0086-missing.h-add-NDA_.patch
Patch86: 0087-udevd-close-race-in-udev-settle.patch
Patch87: 0088-man-document-that-ExecStartPre-is-not-the-place-to-s.patch
Patch88: 0089-journal-fix-return-code.patch
Patch89: 0090-console-fix-error-code-inversion.patch
Patch90: 0091-bus-proxy-complain-only-once-about-queue-overflows.patch
Patch91: 0092-cgtop-fix-assert-when-not-on-tty.patch
Patch92: 0093-man-split-paragraph.patch
Patch93: 0094-hwdb-update.patch
Patch94: 0095-networkd-Begin-with-serial-number-1-for-netlink-requ.patch
Patch95: 0096-journal-remote-downgrade-routine-messages-to-debug.patch
Patch96: 0097-journal-remote-process-events-without-delay.patch
Patch97: 0098-man-update-example-2-in-systemd.network-5.patch
Patch98: 0099-gpt-auto-generator-fix-detection-of-srv.patch
Patch99: 0100-sd-rtnl-never-set-serial-to-0.patch
Patch100: 0101-gpt-auto-generator-allow-type-check-to-fail.patch
Patch101: 0102-man-fix-a-bunch-of-links.patch
Patch102: 0103-man-link-to-fd.o-for-dbus-stuff.patch
Patch103: 0104-man-fix-name-of-systemd.resource-control-5.patch
Patch104: 0105-selinux-fix-SEGV-during-switch-root-if-SELinux-polic.patch
Patch105: 0106-service-don-t-add-After-dependencies-on-.busname-uni.patch
Patch106: 0107-libudev-monitor-fix-error-path-in-send_device.patch
Patch107: 0108-core-remove-left-over-debug-message.patch
Patch108: 0109-units-there-is-no-systemd-udev-hwdb-update.service.patch
Patch109: 0110-util-remove-redundant-debug-message.patch
Patch110: 0111-tmpfiles-remove-redundant-debug-message.patch
Patch111: 0112-sysv-generator-initialize-LookupPaths-just-once.patch
Patch112: 0113-core-do-not-use-quotes-around-virt-and-arch.patch
Patch113: 0114-udev-downgrade-has-devpath-and-filled-with-db-file-m.patch
Patch114: 0115-cryptsetup-generator-remove-warning-about-crypttab-a.patch
Patch115: 0116-sysctl-tweak-debug-message.patch
Patch116: 0117-journald-add-syslog-fields-for-audit-messages.patch
Patch117: 0118-core-remove-useless-debug-message.patch
Patch118: 0119-man-standard-conf-change-directory-reference-to-wild.patch
Patch119: 0120-core-don-t-change-removed-devices-to-state-tentative.patch
Patch120: 0121-fstab-generator-ignore-invalid-swap-priority.patch
Patch121: 0122-missing.h-add-more-btrfs-types-and-defines.patch
Patch122: 0123-build-sys-add-configure-option-to-disableLTO-gold.patch
Patch123: 0124-rules-bring-back-80-net-name-slot.rules.patch
Patch124: 0125-Revert-journald-allow-restarting-journald-without-lo.patch
Patch125: 0126-Revert-man-switch-yum-to-dnf-for-Fedora.patch
Patch126: 0127-journal-remove-audit-socket-unit-files.patch
Patch127: 0128-factory-we-don-t-want-that.patch
Patch128: 0129-timedated-flip-internal-status-after-executing-opera.patch
Patch129: 0130-timedated-fix-enable-disable-reversal.patch
Patch130: 0131-core-make-SELinux-enable-disable-check-symmetric.patch
Patch131: 0132-shared-add-path_compare-an-ordering-path-comparison.patch
Patch132: 0133-core-namespace-fix-path-sorting.patch
Patch133: 0134-machine-do-not-rely-on-asprintf-setting-arg-on-error.patch
Patch134: 0135-some-compilators-don-t-support-__INCLUDE_LEVEL__.patch
Patch135: 0136-udev-net_id-support-multi-port-enpo-device-names.patch
Patch136: 0137-udev-net_id-improve-comments.patch
Patch137: 0138-udev-restore-udevadm-settle-timeout.patch
Patch138: 0139-udev-settle-should-return-immediately-when-timeout-i.patch
Patch139: 0140-udev-Fix-ping-timeout-when-settle-timeout-is-0.patch
Patch140: 0141-detect-virt-use-proc-device-tree.patch
Patch141: 0142-ARM-detect-virt-detect-Xen.patch
Patch142: 0143-ARM-detect-virt-detect-QEMU-KVM.patch
Patch143: 0144-Persistent-by_path-links-for-ata-devices.patch
Patch144: 0145-man-document-forwarding-to-syslog-better.patch
Patch145: 0146-man-fix-typos-in-previous-comimt.patch
Patch146: 0147-LSB-always-add-network-online.target-to-services-wit.patch
Patch147: 0148-rules-enable-memory-hotplug.patch
Patch148: 0149-rules-reload-sysctl-settings-when-the-bridge-module-.patch
Patch149: 0150-console-getty.service-don-t-start-when-dev-console-i.patch
Patch150: 0151-resolved-Do-not-add-.busname-dependencies-when-compi.patch
Patch151: 0152-man-add-journal-remote.conf-5.patch
Patch152: 0153-mount-don-t-run-quotaon-only-for-network-filesystems.patch
Patch153: 0154-mount-fix-up-wording-in-the-comment.patch
Patch154: 0155-udev-net_id-fix-copy-paste-error.patch
Patch155: 0156-man-don-t-mention-journalctl-dev-sda.patch
Patch156: 0157-units-move-After-systemd-hwdb-update.service-depende.patch
Patch157: 0158-units-explicitly-order-systemd-user-sessions.service.patch
Patch158: 0159-zsh-completion-update-loginctl.patch
Patch159: 0160-zsh-completion-add-missing-M-completion-for-journalc.patch
Patch160: 0161-zsh-completion-update-hostnamectl.patch
Patch161: 0162-shell-completion-systemctl-switch-root-verb.patch
Patch162: 0163-core-automount-beef-up-error-message.patch
Patch163: 0164-man-remove-fs-from-rootfsflags.patch
Patch164: 0165-shared-fix-memleak.patch
Patch165: 0166-udevd-fix-synchronization-with-settle-when-handling-.patch
Patch166: 0167-python-systemd-fix-is_socket_inet-to-cope-with-ports.patch
Patch167: 0168-man-fix-examples-indentation-in-tmpfiles.d-5.patch
Patch168: 0169-systemctl-avoid-bumping-NOFILE-rlimit-unless-needed.patch
Patch169: 0170-exit-status-Fix-NOTINSSTALLED-typo.patch
Patch170: 0171-tmpfiles-there-s-no-systemd-forbid-user-logins.servi.patch
Patch171: 0172-kmod-setup-load-ip_tables-kmod-at-boot.patch
Patch172: 0173-util-Fix-assertion-in-split-on-missing.patch
Patch173: 0174-units-set-KillMode-mixed-for-our-daemons-that-fork-w.patch
Patch174: 0175-unit-don-t-add-automatic-dependencies-on-device-unit.patch
Patch175: 0176-update-done-ignore-nanosecond-file-timestamp-compone.patch
Patch176: 0177-sd-daemon-simplify-sd_pid_notify_with_fds.patch
Patch177: 0178-fstab-generator-add-x-systemd.requires-and-x-systemd.patch
Patch178: 0179-core-Fix-assertion-with-empty-Exec-paths.patch
Patch179: 0180-rules-load-sg-module.patch
Patch180: 0181-util-add-shell_maybe_quote-call-for-preparing-a-stri.patch
Patch181: 0182-bus-util-be-more-verbose-if-dbus-job-fails.patch
Patch182: 0183-notify-fix-badly-backported-help-message.patch
Patch183: 0184-cryptsetup-craft-a-unique-ID-with-the-source-device.patch
Patch184: 0185-systemctl-introduce-now-for-enable-disable-and-mask.patch
Patch185: 0186-udev-also-create-old-sas-paths.patch
Patch186: 0187-journald-do-not-strip-leading-whitespace-from-messag.patch
Patch187: 0188-Revert-core-one-step-back-again-for-nspawn-we-actual.patch
Patch188: 0189-bus-creds-always-set-SD_BUS_CREDS_PID-when-we-set-pi.patch
Patch189: 0190-sd-bus-do-not-use-per-datagram-auxiliary-information.patch
Patch190: 0191-sd-bus-store-selinux-context-at-connection-time.patch
Patch191: 0192-journald-simplify-context-handling.patch
Patch192: 0193-bash-completion-add-verb-set-property.patch
Patch193: 0194-sd-bus-don-t-inherit-connection-creds-into-message-c.patch
Patch194: 0195-udev-fix-crash-in-path_id-builtin.patch
Patch195: 0196-sysv-generator-test-Fix-assertion.patch
Patch196: 0197-man-avoid-line-break-in-url.patch
Patch197: 0198-Add-VARIANT-as-a-standard-value-for-etc-os-release.patch
Patch198: 0199-Fix-permissions-on-run-systemd-nspawn-locks.patch
Patch199: 0200-generators-rename-add_-root-usr-_mount-to-add_-sysro.patch
Patch200: 0201-Generate-systemd-fsck-root.service-in-the-initramfs.patch
Patch201: 0202-units-fix-typo-in-systemd-resolved.service.patch
Patch202: 0203-core-don-t-consider-umask-for-SocketMode.patch
Patch203: 0204-timedate-fix-memory-leak-in-timedated.patch
Patch204: 0205-coredump-make-sure-we-vacuum-by-default.patch
Patch205: 0206-tmpfiles-don-t-fail-if-we-cannot-create-a-subvolume-.patch
Patch206: 0207-resolved-fix-crash-when-shutting-down.patch
Patch207: 0208-resolved-allow-DnsAnswer-objects-with-no-space-for-R.patch
Patch208: 0209-id128-add-new-sd_id128_is_null-call.patch
Patch209: 0210-journalctl-Improve-boot-ID-lookup.patch
Patch210: 0211-test-hashmap-fix-an-assert.patch
Patch211: 0212-units-make-sure-systemd-nspawn-.slice-instances-are-.patch
Patch212: 0213-Revert-journald-audit-exit-gracefully-in-the-case-we.patch
Patch213: 0214-journald-handle-more-gracefully-when-bind-fails-on-a.patch
Patch214: 0215-udev-link-config-fix-corruption.patch
Patch215: 0216-udev-net_id-Only-read-the-first-64-bytes-of-PCI-conf.patch
Patch216: 0217-shared-generator-correct-path-to-systemd-fsck.patch
Patch217: 0218-logind-Save-the-user-s-state-when-a-session-enters-S.patch
Patch218: 0219-small-fix-ru-translation.patch
Patch219: 0220-kmod-setup-don-t-warn-when-ipv6-can-t-be-loaded.patch
Patch220: 0221-Partially-revert-ma-setup-simplify.patch
Patch221: 0222-ima-setup-write-policy-one-line-at-a-time.patch
Patch222: 0223-ata_id-unbotch-format-specifier.patch
Patch223: 0224-install-explicitly-return-0-on-success.patch
Patch224: 0225-systemd.service.xml-document-that-systemd-removes-th.patch
Patch225: 0226-core-handle-log-target-null-when-calling-systemd-shu.patch
Patch226: 0227-man-ProtectHome-protects-root-as-well.patch
Patch227: 0228-timedatectl-trim-non-local-RTC-warning-to-80-chars-w.patch
Patch228: 0229-escape-fix-exit-code.patch
Patch229: 0230-man-information-about-available-properties.patch
Patch230: 0231-journal-in-persistent-mode-create-var-log-journal-wi.patch
Patch231: 0232-sysv-generator-fix-wrong-Overwriting-existing-symlin.patch
Patch232: 0233-mount-don-t-claim-a-device-is-gone-from-proc-self-mo.patch
Patch233: 0234-mount-properly-check-for-mounts-currently-in-proc-se.patch
Patch234: 0235-units-add-Install-section-to-tmp.mount.patch
Patch235: 0236-bus-util-add-articles-to-explanation-messages.patch
Patch236: 0237-bus-util-print-correct-warnings-for-units-that-fail-.patch
Patch237: 0238-Revert-journald-move-dev-log-socket-to-run.patch
Patch238: 0239-journald-server-don-t-read-audit-events.patch
Patch239: 0240-everything-remove-traces-of-user.patch
Patch240: 0241-selinux-fix-check-for-transient-units.patch
Patch241: 0242-socket-fix-setsockopt-call.-SOL_SOCKET-changed-to-SO.patch
Patch242: 0243-selinux-fix-missing-SELinux-unit-access-check.patch
Patch243: 0244-selinux-always-use-_raw-API-from-libselinux.patch
Patch244: 0245-udev-net_id-support-predictable-ifnames-on-virtio-bu.patch
Patch245: 0246-Revert-sysctl.d-default-to-fq_codel-fight-bufferbloa.patch
Patch246: 0247-loginctl-print-nontrivial-properties-in-logictl-show.patch
Patch247: 0248-login-fix-label-on-run-nologin.patch
Patch248: 0249-udev-rules-prandom-character-device-node-permissions.patch
Patch249: 0250-login-fix-gcc-warning-include-missing-header-file.patch
Patch250: 0251-shutdown-make-sure-run-nologin-has-correct-label.patch
Patch251: 0252-sd-event-fix-prepare-priority-queue-comparison-funct.patch
Patch252: 0253-units-run-ldconfig-also-when-cache-is-unpopulated.patch
Patch253: 0254-selinux-fix-regression-of-systemctl-subcommands-when.patch
Patch254: 0255-tmpfiles.d-don-t-clean-SAP-lockfiles-and-logs.patch
Patch255: 0256-udev-make-naming-for-virtio-devices-opt-in.patch
Patch256: 0257-tmpfiles.d-don-t-clean-SAP-sockets-either.patch
Patch257: 0258-run-synchronously-wait-until-the-scope-unit-we-creat.patch
Patch258: 0259-device-rework-how-we-enter-tentative-state.patch
Patch259: 0260-core-Do-not-bind-a-mount-unit-to-a-device-if-it-was-.patch
Patch260: 0261-logind-set-RemoveIPC-no-by-default.patch
Patch261: 0262-sysv-generator-follow-symlinks-in-etc-rc.d-init.d.patch
Patch262: 0263-sysv-generator-test-always-log-to-console.patch
Patch263: 0264-man-RemoveIPC-is-set-to-no-on-rhel.patch
Patch264: 0265-Avoid-tmp-being-mounted-as-tmpfs-without-the-user-s-.patch
Patch265: 0266-test-sysv-generator-Check-for-network-online.target.patch
Patch266: 0267-makefile-disable-udev-tests.patch
Patch267: 0268-arm-aarch64-detect-virt-check-dmi.patch
Patch268: 0269-detect-virt-dmi-look-for-KVM.patch
Patch269: 0270-Revert-journald-turn-ForwardToSyslog-off-by-default.patch
Patch270: 0271-terminal-util-when-resetting-terminals-don-t-wait-fo.patch
Patch271: 0272-basic-terminal-util-introduce-SYSTEMD_COLORS-environ.patch
Patch272: 0273-ask-password-don-t-abort-when-message-is-missing.patch
Patch273: 0274-sysv-generator-do-not-join-dependencies-on-one-line-.patch
Patch274: 0275-udev-fibre-channel-fix-NPIV-support.patch
Patch275: 0276-ata_id-unreverse-WWN-identifier.patch
Patch276: 0277-Fixup-WWN-bytes-for-big-endian-systems.patch
Patch277: 0278-sd-journal-introduce-has_runtime_files-and-has_persi.patch
Patch278: 0279-journalctl-improve-error-messages-when-the-specified.patch
Patch279: 0280-journalctl-show-friendly-info-when-using-b-on-runtim.patch
Patch280: 0281-journalctl-make-journalctl-dev-sda-work.patch
Patch281: 0282-journalctl-add-match-for-the-current-boot-when-calle.patch
Patch282: 0283-man-clarify-what-happens-when-journalctl-is-called-w.patch
Patch283: 0284-core-downgrade-warning-about-duplicate-device-names.patch
Patch284: 0285-udev-downgrade-a-few-warnings-to-debug-messages.patch
Patch285: 0286-man-LEVEL-in-systemd-analyze-set-log-level-is-not-op.patch
Patch286: 0287-Revert-udev-fibre-channel-fix-NPIV-support.patch
Patch287: 0288-udev-path-id-fibre-channel-NPIV-use-fc_vport-s-port_.patch
Patch288: 0289-systemctl-is-active-failed-should-return-0-if-at-lea.patch
Patch289: 0290-rules-set-SYSTEMD_READY-0-on-DM_UDEV_DISABLE_OTHER_R.patch
Patch290: 0291-s390-add-personality-support.patch
Patch291: 0292-socket_address_listen-do-not-rely-on-errno.patch
Patch292: 0293-path_id-reintroduce-by-path-links-for-virtio-block-d.patch
Patch293: 0294-journal-fix-error-handling-when-compressing-journal-.patch
Patch294: 0295-journal-irrelevant-coding-style-fixes.patch
Patch295: 0296-install-follow-unit-file-symlinks-in-usr-but-not-etc.patch
Patch296: 0297-core-look-for-instance-when-processing-template-name.patch
Patch297: 0298-core-improve-error-message-when-starting-template-wi.patch
Patch298: 0299-man-tmpfiles.d-add-note-about-permissions-and-owners.patch
Patch299: 0300-tmpfiles-don-t-follow-symlinks-when-adjusting-ACLs-f.patch
Patch300: 0301-udev-filter-out-non-sensically-high-onboard-indexes-.patch
Patch301: 0302-test-execute-add-tests-for-RuntimeDirectory.patch
Patch302: 0303-core-fix-group-ownership-when-Group-is-set.patch
Patch303: 0304-fstab-generator-cescape-device-name-in-root-fsck-ser.patch
Patch304: 0305-core-add-new-RandomSec-setting-for-time-units.patch
Patch305: 0306-core-rename-Random-to-RandomizedDelay.patch
Patch306: 0307-journal-remote-change-owner-of-var-log-journal-remot.patch
Patch307: 0308-Add-Seal-option-in-the-configuration-file-for-journa.patch
Patch308: 0309-tests-fix-make-check-failure.patch
Patch309: 0310-device-make-sure-to-not-ignore-re-plugged-device.patch
Patch310: 0311-device-Ensure-we-have-sysfs-path-before-comparing.patch
Patch311: 0312-core-fix-memory-leak-on-set-default-enable-disable-e.patch
Patch312: 0313-nspawn-fix-minor-memory-leak.patch
Patch313: 0314-basic-fix-error-memleak-in-socket-util.patch
Patch314: 0315-core-fix-memory-leak-in-manager_run_generators.patch
Patch315: 0316-modules-load-fix-memory-leak.patch
Patch316: 0317-core-fix-memory-leak-on-failed-preset-all.patch
Patch317: 0318-sd-bus-fix-memory-leak-in-test-bus-chat.patch
Patch318: 0319-core-fix-memory-leak-in-transient-units.patch
Patch319: 0320-bus-fix-leak-in-error-path.patch
Patch320: 0321-shared-logs-show-fix-memleak-in-add_matches_for_unit.patch
Patch321: 0322-logind-introduce-LockedHint-and-SetLockedHint-3238.patch
Patch322: 0323-import-use-the-old-curl-api.patch
Patch323: 0324-importd-drop-dkr-support.patch
Patch324: 0325-import-add-support-for-gpg2-for-verifying-imported-i.patch
Patch325: 0326-nspawn-when-connected-to-pipes-for-stdin-stdout-pass.patch
Patch326: 0327-mount-remove-obsolete-n.patch
Patch327: 0328-core-don-t-log-job-status-message-in-case-job-was-ef.patch
Patch328: 0329-core-use-an-AF_UNIX-SOCK_DGRAM-socket-for-cgroup-age.patch
Patch329: 0330-logind-process-session-inhibitor-fds-at-higher-prior.patch
Patch330: 0331-Teach-bus_append_unit_property_assignment-about-Dele.patch
Patch331: 0332-sd-netlink-fix-deep-recursion-in-message-destruction.patch
Patch332: 0333-add-REMOTE_ADDR-and-REMOTE_PORT-for-Accept-yes.patch
Patch333: 0334-core-don-t-dispatch-load-queue-when-setting-Slice-fo.patch
Patch334: 0335-run-make-slice-work-in-conjunction-with-scope.patch
Patch335: 0336-myhostname-fix-timeout-if-ipv6-is-disabled.patch
Patch336: 0337-readahead-do-not-increase-nr_requests-for-root-fs-bl.patch
Patch337: 0338-manager-reduce-complexity-of-unit_gc_sweep-3507.patch
Patch338: 0339-hwdb-selinuxify-a-bit-3460.patch
Patch339: 0340-udevadm-explicitly-relabel-etc-udev-hwdb.bin-after-r.patch
Patch340: 0341-systemctl-return-diffrent-error-code-if-service-exis.patch
Patch341: 0342-systemctl-Replace-init-script-error-codes-with-enum-.patch
Patch342: 0343-systemctl-rework-systemctl-status-a-bit.patch
Patch343: 0344-journal-verify-don-t-hit-SIGFPE-when-determining-pro.patch
Patch344: 0345-journal-avoid-mapping-empty-data-and-field-hash-tabl.patch
Patch345: 0346-journal-when-verifying-journal-files-handle-empty-on.patch
Patch346: 0347-journal-explain-the-error-when-we-find-a-non-DATA-ob.patch
Patch347: 0348-journalctl-properly-detect-empty-journal-files.patch
Patch348: 0349-journal-uppercase-first-character-in-verify-error-me.patch
Patch349: 0350-journalctl-make-sure-journalctl-f-t-unmatched-blocks.patch
Patch350: 0351-journalctl-don-t-print-No-entries-in-quiet-mode.patch
Patch351: 0352-sd-event-expose-the-event-loop-iteration-counter-via.patch
Patch352: 0353-manager-Only-invoke-a-single-sigchld-per-unit-within.patch
Patch353: 0354-manager-Fixing-a-debug-printf-formatting-mistake.patch
Patch354: 0355-core-support-IEC-suffixes-for-RLIMIT-stuff.patch
Patch355: 0356-core-accept-time-units-for-time-based-resource-limit.patch
Patch356: 0357-time-util-add-parse_time-which-is-like-parse_sec-but.patch
Patch357: 0358-core-support-soft-hard-ranges-for-RLIMIT-options.patch
Patch358: 0359-core-fix-rlimit-parsing.patch
Patch359: 0360-core-dump-rlim_cur-too.patch
Patch360: 0361-install-fix-disable-via-unit-file-path.patch
Patch361: 0362-manager-don-t-skip-sigchld-handler-for-main-and-cont.patch
Patch362: 0363-units-increase-watchdog-timeout-to-3min-for-all-our-.patch
Patch363: 0364-core-bump-net.unix.max_dgram_qlen-really-early-durin.patch
Patch364: 0365-core-fix-priority-ordering-in-notify-handling.patch
Patch365: 0366-tests-fix-personality-tests-on-ppc64-and-aarch64.patch
Patch366: 0367-systemctl-consider-service-running-only-when-it-is-i.patch
Patch367: 0368-install-do-not-crash-when-processing-empty-masked-un.patch
Patch368: 0369-Revert-install-fix-disable-via-unit-file-path.patch
Patch369: 0370-systemctl-allow-disable-on-the-unit-file-path-but-wa.patch
Patch370: 0371-tmpfiles-enforce-ordering-when-executing-lines.patch
Patch371: 0372-Introduce-bus_unit_check_load_state-helper.patch
Patch372: 0373-core-use-bus_unit_check_load_state-in-transaction_ad.patch
Patch373: 0374-udev-path_id-correct-segmentation-fault-due-to-missi.patch
Patch374: 0375-rules-load-sg-driver-also-when-scsi_target-appears-4.patch
Patch375: 0376-fix-gcc-warnings-about-uninitialized-variables.patch
Patch376: 0377-journalctl-rework-code-that-checks-whether-we-have-a.patch
Patch377: 0378-journalctl-Improve-boot-ID-lookup.patch
Patch378: 0379-journalctl-only-have-a-single-exit-path-from-main.patch
Patch379: 0380-journalctl-free-all-command-line-argument-objects.patch
Patch380: 0381-journalctl-rename-boot_id_t-to-BootId.patch
Patch381: 0382-util-introduce-CMSG_FOREACH-macro-and-make-use-of-it.patch
Patch382: 0383-journald-don-t-employ-inner-loop-for-reading-from-in.patch
Patch383: 0384-journald-fix-count-of-object-meta-fields.patch
Patch384: 0385-journal-cat-return-a-correct-error-not-1.patch
Patch385: 0386-journalctl-introduce-short-options-for-since-and-unt.patch
Patch386: 0387-journal-s-Envalid-Invalid.patch
Patch387: 0388-journald-dispatch-SIGTERM-SIGINT-with-a-low-priority.patch
Patch388: 0389-lz4-fix-size-check-which-had-no-chance-of-working-on.patch
Patch389: 0390-journal-normalize-priority-of-logging-sources.patch
Patch390: 0391-Fix-miscalculated-buffer-size-and-uses-of-size-unlim.patch
Patch391: 0392-journal-Drop-monotonicity-check-when-appending-to-jo.patch
Patch392: 0393-journalctl-unify-how-we-free-boot-id-lists-a-bit.patch
Patch393: 0394-journalctl-don-t-trust-the-per-field-entry-tables-wh.patch
Patch394: 0395-units-remove-udev-control-socket-when-systemd-stops-.patch
Patch395: 0396-logind-don-t-assert-if-the-slice-is-missing.patch
Patch396: 0397-core-enable-transient-unit-support-for-slice-units.patch
Patch397: 0398-sd-bus-bump-message-queue-size.patch
Patch398: 0399-install-fix-disable-when-etc-systemd-system-is-a-sym.patch
Patch399: 0400-rules-add-NVMe-rules-3136.patch
Patch400: 0401-rules-introduce-disk-by-id-model_serial-symlinks-for.patch
Patch401: 0402-rules-fix-for-possible-whitespace-in-the-model-attri.patch
Patch402: 0403-systemctl-pid1-do-not-warn-about-missing-install-inf.patch
Patch403: 0404-systemctl-core-ignore-masked-units-in-preset-all.patch
Patch404: 0405-shared-install-handle-dangling-aliases-as-an-explici.patch
Patch405: 0406-shared-install-ignore-unit-symlinks-when-doing-prese.patch
Patch406: 0407-40-redhat.rules-don-t-hoplug-memory-on-s390x.patch
Patch407: 0408-If-the-notification-message-length-is-0-ignore-the-m.patch
Patch408: 0409-systemctl-suppress-errors-with-show-for-nonexistent-.patch
Patch409: 0410-40-redhat.rules-disable-auto-online-of-hot-plugged-m.patch
Patch410: 0411-pid1-don-t-return-any-error-in-manager_dispatch_noti.patch
Patch411: 0412-pid1-process-zero-length-notification-messages-again.patch
Patch412: 0413-pid1-more-informative-error-message-for-ignored-noti.patch
Patch413: 0414-manager-219-needs-u-id-in-log_unit_debug.patch
Patch414: 0415-virt-add-possibility-to-skip-the-check-for-chroot.patch
Patch415: 0416-load-fragment-fix-parsing-values-in-bytes-and-preven.patch
Patch416: 0417-core-fix-assertion-check.patch
Patch417: 0418-tmp.mount.hm4-After-swap.target-3087.patch
Patch418: 0419-make-sure-all-swap-units-are-ordered-before-the-swap.patch
Patch419: 0420-Recognise-Lustre-as-a-remote-file-system-4530.patch
Patch420: 0421-unit-don-t-add-Requires-for-tmp.mount.patch
Patch421: 0422-core-return-0-from-device_serialize.patch
Patch422: 0423-mtd_probe-include-stdint.patch
Patch423: 0424-tests-fix-failure-of-test-execute-if-dev-mem-is-not-.patch
Patch424: 0425-sd-journal-properly-export-has_-persistent-runtime-_.patch
Patch425: 0426-core-add-possibility-to-set-action-for-ctrl-alt-del-.patch
Patch426: 0427-failure-action-generalize-failure-action-to-emergenc.patch
Patch427: 0428-core-use-emergency_action-for-ctr-alt-del-burst.patch
Patch428: 0429-udev-path_id-introduce-support-for-NVMe-devices-4169.patch
Patch429: 0430-core-fix-CapabilityBoundingSet-merging.patch
Patch430: 0431-core-fix-capability-bounding-set-parsing.patch
Patch431: 0432-core-make-parsing-of-RLIMIT_NICE-aware-of-actual-nic.patch
Patch432: 0433-shared-fix-double-free-in-unmask-5005.patch
Patch433: 0434-shared-fix-double-free-in-link.patch
Patch434: 0435-shared-check-strdup-NULL.patch
Patch435: 0436-core-improve-error-message-when-RefuseManualStart-St.patch
Patch436: 0437-systemctl-fix-is-enabled-exit-status-on-failure-when.patch
Patch437: 0438-man-document-that-the-automatic-journal-limits-are-c.patch
Patch438: 0439-random-seed-raise-POOL_SIZE_MIN-to-1024.patch
Patch439: 0440-bash-completion-add-support-for-now-5155.patch
Patch440: 0441-basic-fix-touch-creating-files-with-07777-mode.patch
Patch441: 0442-udev-net_id-add-support-for-phys_port_name-attribute.patch
Patch442: 0443-install-introduce-UnitFileFlags.patch
Patch443: 0444-shared-systemctl-teach-is-enabled-to-show-installati.patch
Patch444: 0445-udev-fix-crash-with-invalid-udev.log-priority.patch
Patch445: 0446-core-make-exec-code-a-bit-more-readable.patch
Patch446: 0447-core-Private-Protect-options-with-RootDirectory.patch
Patch447: 0448-core-if-the-start-command-vanishes-during-runtime-do.patch
Patch448: 0449-systemctl-make-sure-that-now-is-carried-out-5209.patch
Patch449: 0450-udev-inform-systemd-how-many-workers-we-can-potentia.patch
Patch450: 0451-service-log_unit-consumes-id-of-unit-not-a-unit.patch
Patch451: 0452-automount-add-expire-support.patch
Patch452: 0453-fstab-generator-fix-memleak.patch
Patch453: 0454-remove-bus-proxyd.patch
Patch454: 0455-execute-Add-new-PassEnvironment-directive.patch
Patch455: 0456-test-execute-Add-tests-for-new-PassEnvironment-direc.patch
Patch456: 0457-test-execute-Clarify-interaction-of-PassEnvironment-.patch
Patch457: 0458-load-fragment-resolve-specifiers-in-RuntimeDirectory.patch
Patch458: 0459-Add-microphone-mute-keymap-for-Dell-Precision.patch
Patch459: 0460-hwdb-update-micmute-YCODE-on-device-node-at-DELL-LAT.patch
Patch460: 0461-udev-path_id-improve-and-enhance-bus-detection-for-L.patch
Patch461: 0462-core-port-config_parse_bounding_set-to-extract_first.patch
Patch462: 0463-core-simplify-parsing-of-capability-bounding-set-set.patch
Patch463: 0464-test-add-test-for-capability-bounding-set-parsing.patch
Patch464: 0465-capabilities-keep-bounding-set-in-non-inverted-forma.patch
Patch465: 0466-capabilities-added-support-for-ambient-capabilities.patch
Patch466: 0467-man-add-AmbientCapabilities-entry.patch
Patch467: 0468-test-capability-rebase-to-upstream-version.patch
Patch468: 0469-namespace-don-t-fail-on-masked-mounts.patch
Patch469: 0470-sysv-generator-Provides-network-should-also-pull-net.patch
Patch470: 0471-Install-correctly-report-symlink-creations.patch
Patch471: 0472-rules-40-redhat.rules-rules-should-be-on-one-line.patch
Patch472: 0473-tmpfiles-add-new-e-action-which-cleans-up-a-dir-with.patch
Patch473: 0474-util-bind_remount_recursive-handle-return-0-of-set_c.patch
Patch474: 0475-core-add-support-for-the-pids-cgroup-controller.patch
Patch475: 0476-core-add-new-DefaultTasksMax-setting-for-system.conf.patch
Patch476: 0477-logind-add-a-new-UserTasksMax-setting-to-logind.conf.patch
Patch477: 0478-core-support-percentage-specifications-on-TasksMax.patch
Patch478: 0479-core-reinstate-propagation-of-stop-restart-jobs-via-.patch
Patch479: 0480-core-when-propagating-restart-requests-due-to-deps-d.patch
Patch480: 0481-core-properly-handle-jobs-that-are-suppressed-to-JOB.patch
Patch481: 0482-tests-set-tasks_max-to-infinity.patch
Patch482: 0483-Avoid-forever-loop-for-journalctl-list-boots-command.patch
Patch483: 0484-sd-journal-return-SD_JOURNAL_INVALIDATE-only-if-jour.patch
Patch484: 0485-load-fragment-don-t-print-error-about-incorrect-synt.patch
Patch485: 0486-core-manager-add-some-missing-dbus-properties.patch
Patch486: 0487-core-manager-expose-DefaultLimit-as-properties-on-db.patch
Patch487: 0488-fstab-generator-remove-bogus-condition.patch
Patch488: 0489-readahead-collect-don-t-print-warning-message-when-h.patch
Patch489: 0490-tmpfiles-don-t-recursively-descend-into-journal-dire.patch
Patch490: 0491-tmpfiles-also-set-acls-on-var-log-journal.patch
Patch491: 0492-tmpfiles-set-acls-on-system.journal-explicitly.patch
Patch492: 0493-sysctl-configure-kernel-parameters-in-the-order-they.patch
Patch493: 0494-units-drop-explicit-NotifyAccess-setting-from-journa.patch
Patch494: 0495-systemd-notify-Always-pass-a-valid-pid-to-sd_pid_not.patch
Patch495: 0496-sd_pid_notify_with_fds-fix-computing-msg_controllen.patch
Patch496: 0497-rules-move-cpu-hotplug-rule-to-separate-file.patch
Patch497: 0498-Revert-rules-move-cpu-hotplug-rule-to-separate-file.patch
Patch498: 0499-tests-use-XFS-as-root-filesystem-for-system-tests.patch
Patch499: 0500-tests-use-fdisk-instead-of-sfdisk.patch
Patch500: 0501-Revert-udev-net_id-add-support-for-phys_port_name-at.patch
Patch501: 0502-core-unset-sysfs-path-after-transition-to-dead-state.patch
Patch502: 0503-sysctl-fix-uninitialized-variable.patch
Patch503: 0504-udev-ignore-SIGCHLD-from-unexpected-processes-130653.patch
Patch504: 0505-compile-with-Werror.patch
Patch505: 0506-myhostname-don-t-return-any-ipv6-entries-when-ipv6-i.patch
Patch506: 0507-core-execute-fix-fork-fail-handling-in-exec_spawn.patch
Patch507: 0508-fix-compilation-after-commit-382877acc6c029e59e359a0.patch
Patch508: 0509-Redefine-32bit-time_t-format-to-signed.patch
Patch509: 0510-sd-bus-bus-kernel.c-fix-format-errors-on-ppc64le.patch
Patch510: 0511-tmpfiles-with-e-don-t-attempt-to-set-permissions-whe.patch
Patch511: 0512-units-introduce-getty-pre.target-6667.patch
Patch512: 0513-units-order-container-and-console-getty-units-after-.patch
Patch513: 0514-log-never-log-into-foreign-fd-2-in-PID-1-or-its-pre-.patch
Patch514: 0515-nspawn-new-option-to-start-as-PID2.patch
Patch515: 0516-journal-implicitly-flush-to-var-on-recovery-4028.patch
Patch516: 0517-journal-add-use-flushed_flag_is_set-helper-4041.patch
Patch517: 0518-journald-don-t-flush-to-var-log-journal-before-we-ge.patch
Patch518: 0519-path-util-make-use-of-mnt_id-field-exported-in-proc-.patch
Patch519: 0520-Revert-Revert-journald-allow-restarting-journald-wit.patch
Patch520: 0521-journald-make-sure-we-retain-all-stream-fds-across-r.patch
Patch521: 0522-Allow-systemd-tmpfiles-to-set-the-file-directory-att.patch
Patch522: 0523-tmpfiles-rework-file-attribute-code.patch
Patch523: 0524-tmpfiles-warn-if-we-get-an-argument-on-lines-that-do.patch
Patch524: 0525-tmpfiles-substitute-specifiers-in-arguments-for-writ.patch
Patch525: 0526-btrfs-util-introduce-btrfs_is_filesystem-and-make-us.patch
Patch526: 0527-journal-don-t-force-FS_NOCOW_FL-on-new-journal-files.patch
Patch527: 0528-tmpfiles-Add-C-attrib-to-the-journal-files-directori.patch
Patch528: 0529-Revert-path-util-make-use-of-mnt_id-field-exported-i.patch
Patch529: 0530-device-make-sure-to-remove-all-device-units-sharing-.patch
Patch530: 0531-manager-when-reexecuting-try-to-connect-to-bus-only-.patch
Patch531: 0532-doc-document-service-exit-codes.patch
Patch532: 0533-units-order-cryptsetup-pre.target-before-cryptsetup.patch
Patch533: 0534-man-add-an-explicit-description-of-_netdev-to-system.patch
Patch534: 0535-units-add-remote-cryptsetup.target-and-remote-crypts.patch
Patch535: 0536-cryptsetup-generator-use-remote-cryptsetup.target-wh.patch
Patch536: 0537-Support-rdma-as-a-ListenNetlink-argument-6626.patch
Patch537: 0538-core-namespace-Protect-usr-instead-of-home-with-Prot.patch
Patch538: 0539-udev-Use-parent-bus-id-for-virtio-disk-builtin-path-.patch
Patch539: 0540-socket-util-socket_address_parse-should-not-log-erro.patch
Patch540: 0541-test-fix-failing-test-socket-util-when-running-with-.patch
Patch541: 0542-scsi_id-add-missing-options-to-getopt_long-6501.patch
Patch542: 0543-unmount-Pass-in-mount-options-when-remounting-read-o.patch
Patch543: 0544-shutdown-don-t-remount-ro-network-filesystems.-6588.patch
Patch544: 0545-shutdown-fix-incorrect-fscanf-result-check-6806.patch
Patch545: 0546-path-util-make-use-of-mnt_id-field-exported-in-proc-.patch
Patch546: 0547-support-ranges-when-parsing-CPUAffinity.patch
Patch547: 0548-man-Update-man-page-documentation-for-CPUAffinity.patch
Patch548: 0549-test-path-util-force-rm_rf.patch
Patch549: 0550-Export-NVMe-WWID-udev-attribute-5348.patch
Patch550: 0551-mount-make-sure-we-unmount-tmpfs-mounts-before-we-de.patch
Patch551: 0552-journald-never-accept-fds-from-file-systems-with-man.patch
Patch552: 0553-udev-builtin-keyboard-move-fetching-the-device-node-.patch
Patch553: 0554-udev-builtin-keyboard-immediately-EVIOCSKEYCODE-when.patch
Patch554: 0555-udev-builtin-keyboard-move-actual-key-mapping-to-a-h.patch
Patch555: 0556-udev-builtin-keyboard-invert-a-condition.patch
Patch556: 0557-udev-builtin-keyboard-add-support-for-EVDEV_ABS_.patch
Patch557: 0558-hwdb-sync-60-evdev.hwdb-from-systemd-v235.patch
Patch558: 0559-journal-ensure-open-journals-from-find_journal-3973.patch
Patch559: 0560-journal-only-check-available-space-when-journal-is-o.patch
Patch560: 0561-automount-if-an-automount-unit-is-masked-don-t-react.patch
Patch561: 0562-units-add-Install-section-to-remote-cryptsetup.targe.patch
Patch562: 0563-units-replace-remote-cryptsetup-pre.target-with-remo.patch
Patch563: 0564-man-add-a-note-about-_netdev-usage.patch
Patch564: 0565-units-make-remote-cryptsetup.target-also-after-crypt.patch
Patch565: 0566-cryptsetup-generator-use-after-free.patch
Patch566: 0567-manager-fix-connecting-to-bus-when-dbus-is-actually-.patch
Patch567: 0568-journal-remote-make-url-option-support-arbitrary-url.patch
Patch568: 0569-journald-make-maximum-size-of-stream-log-lines-confi.patch
Patch569: 0570-service-serialize-information-about-currently-execut.patch
Patch570: 0571-tests-add-new-test-for-issue-518.patch
Patch571: 0572-tests-in-RHEL-7-we-don-t-have-python3-by-default.patch
Patch572: 0573-service-attempt-to-execute-next-main-command-only-fo.patch
Patch573: 0574-timedatectl-stop-using-xstrftime.patch
Patch574: 0575-Add-support-to-read-lz4-compressed-journals.patch
Patch575: 0576-journald-never-block-when-sending-messages-on-NOTIFY.patch
Patch576: 0577-journal-restore-watchdog-support.patch
Patch577: 0578-cgroup-resource-property-setting-ignored-if-einval.patch
Patch578: 0579-fileio-add-new-helper-call-read_line-as-bounded-getl.patch
Patch579: 0580-def-add-new-constant-LONG_LINE_MAX.patch
Patch580: 0581-fileio-rework-read_one_line_file-on-top-of-read_line.patch
Patch581: 0582-cgroup-util-replace-one-use-of-fgets-by-read_line.patch
Patch582: 0583-conf-parse-remove-4K-line-length-limit.patch
Patch583: 0584-test-conf-parser-add-tests-for-config-parser.patch
Patch584: 0585-fileio-use-_cleanup_-for-FILE-unlocking.patch
Patch585: 0586-test-fileio-also-test-read_line-with-actual-files.patch
Patch586: 0587-fileio-return-0-from-read_one_line_file-on-success.patch
Patch587: 0588-man-fix-description-of-force-in-halt-8-7392.patch
Patch588: 0589-journal-return-better-error-for-empty-files.patch
Patch589: 0590-journalctl-continue-operation-even-if-we-run-into-an.patch
Patch590: 0591-journal-remove-error-check-that-never-happens.patch
Patch591: 0592-sd-journal-various-clean-ups-and-modernizations.patch
Patch592: 0593-journalctl-when-we-fail-to-open-a-journal-file-print.patch
Patch593: 0594-journald-fix-accuracy-of-watchdog-timer-event.patch
Patch594: 0595-core-fix-the-reversed-sanity-check-when-setting-Star.patch
Patch595: 0596-shared-dropin-ignore-ENAMETOOLONG-when-checking-drop.patch
Patch596: 0597-cryptsetup-when-unlocking-always-put-path-to-the-obj.patch
Patch597: 0598-cryptsetup-use-more-descriptive-name-for-the-variabl.patch
Patch598: 0599-cryptsetup-generator-do-not-bind-to-the-decrypted-de.patch
Patch599: 0600-shared-cgroup-utils-_CGROUP_CONTROLLER_MASK_ALL-does.patch
Patch600: 0601-automount-ack-automount-requests-even-when-already-m.patch
Patch601: 0602-udev-net_id-add-support-for-platform-bus-ACPI-mostly.patch
Patch602: 0603-journald-native-Fix-typo-in-MANDLOCK-message.patch
Patch603: 0604-process-util-make-our-freeze-routine-do-something-us.patch
Patch604: 0605-dbus-propagate-errors-from-bus_init_system-and-bus_i.patch
Patch605: 0606-bus-util.c-fix-TasksMax-property-assignment.patch
Patch606: 0607-sparse-avoid-clash-with-__bitwise-and-__force-from-4.patch
Patch607: 0608-core-Let-two-more-booleans-survive-a-daemon-reload.patch
Patch608: 0609-core-don-t-choke-if-a-unit-another-unit-triggers-van.patch
Patch609: 0610-sd-journal-properly-handle-inotify-queue-overflow.patch
Patch610: 0611-sd-journal-make-sure-it-s-safe-to-call-sd_journal_pr.patch
Patch611: 0612-journalctl-Periodically-call-sd_journal_process-in-j.patch
Patch612: 0613-sd-journal-when-picking-up-a-new-file-compare-inode-.patch
Patch613: 0614-umount-always-use-MNT_FORCE-in-umount_all-7213.patch
Patch614: 0615-core-Implement-timeout-based-umount-remount-limit.patch
Patch615: 0616-core-Implement-sync_with_progress.patch
Patch616: 0670-Refuse-dbus-message-paths-longer-than-BUS_PATH_SIZE_.patch
Patch617: 0671-Allocate-temporary-strings-to-hold-dbus-paths-on-the.patch
Patch618: 0672-sd-bus-if-we-receive-an-invalid-dbus-message-ignore-.patch
Patch619: 0735-udev-check-if-the-spawned-PID-didn-t-exit-after-reap.patch
Patch620: 0736-udev-call-poll-again-after-killing-the-spawned-proce.patch
Patch621: 0737-udev-check-age-against-both-timeouts-to-prevent-inte.patch
Patch622: 0738-avoid-possible-hang-if-our-child-process-hangs.patch
Patch623: 0739-UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG.patch
Patch624: 0001-time-util-Introduce-parse_sec_def_infinity.patch
Patch625: 0001-core-add-CPUQuotaPeriodSec.patch
Patch626: CA-117731.patch
Patch627: net-ifnames.patch
Patch628: disable-journal.patch
Patch629: journal-disable-kmsg.patch
Patch630: disable-acpi-events.patch
Patch631: allow-tag-nomatch.patch
Patch632: fix-mtd_probe-build.patch
Patch633: CP-32988_maxmemory_as_percentage_from_upstream.patch
# Preset policy is in rhel-release package
# we are just disabling everything
Source1: 99-default-disable.preset
# Prevent accidental removal of the systemd package
Source2: yum-protect-systemd.conf
# SysV convert script.
Source3: systemd-sysv-convert
# ship /etc/rc.d/rc.local https://bugzilla.redhat.com/show_bug.cgi?id=968401
Source4: rc.local
#https://bugzilla.redhat.com/show_bug.cgi?id=1032711
Source5: 60-alias-kmsg.rules
# Stop-gap, just to ensure things work fine with rsyslog without having to change the package right-away
Source6: listen.conf
# Generating translations is sometimes broken, let's ship the translated policy files directly in sources
Source7: org.freedesktop.hostname1.policy
Source8: org.freedesktop.import1.policy
Source9: org.freedesktop.locale1.policy
Source10: org.freedesktop.login1.policy
Source11: org.freedesktop.machine1.policy
Source12: org.freedesktop.systemd1.policy
Source13: org.freedesktop.timedate1.policy
Source14: phys-port-name-gen
Source15: 76-phys-port-name.rules
Source16: 76-phys-port-name.conf

BuildRequires:  libcap-devel
BuildRequires:  tcp_wrappers-devel
BuildRequires:  pam-devel
BuildRequires:  libselinux-devel
BuildRequires:  audit-libs-devel
BuildRequires:  cryptsetup-devel
BuildRequires:  dbus-devel
BuildRequires:  libacl-devel
BuildRequires:  pciutils-devel
BuildRequires:  glib2-devel
BuildRequires:  gobject-introspection-devel
BuildRequires:  libblkid-devel
BuildRequires:  xz-devel
BuildRequires:  zlib-devel
BuildRequires:  bzip2-devel
BuildRequires:  lz4-devel
BuildRequires:  libidn-devel
BuildRequires:  libcurl-devel
BuildRequires:  kmod-devel
BuildRequires:  elfutils-devel
BuildRequires:  libgcrypt-devel
BuildRequires:  gnutls-devel
BuildRequires:  qrencode-devel
BuildRequires:  libmicrohttpd-devel
BuildRequires:  libxslt
BuildRequires:  docbook-style-xsl
BuildRequires:  pkgconfig
BuildRequires:  intltool
BuildRequires:  gperf
BuildRequires:  gawk
BuildRequires:  gtk-doc
BuildRequires:  python2-devel
BuildRequires:  python-lxml
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  git
BuildRequires:  libmount-devel
%{?_cov_buildrequires}

Requires(post): coreutils
Requires(post): gawk
Requires(post): sed
Requires(post): acl
Requires(pre):  coreutils
Requires(pre):  /usr/bin/getent
Requires(pre):  /usr/sbin/groupadd
Requires:       dbus
Requires:       %{name}-libs = %{version}-%{release}
Requires:       kmod >= 18-4
Requires:       system-release >= 7.0
Requires:       diffutils

Provides:       /bin/systemctl
Provides:       /sbin/shutdown
Provides:       syslog
Provides:       systemd-units = %{version}-%{release}

Conflicts:      dracut < 033-243
Conflicts:      initscripts < 9.49.28-1

#Obsolete packages when we are migrating from rhel6
Provides:       udev = %{version}
Obsoletes:      udev < 183
Obsoletes:      system-setup-keyboard < 0.9
Provides:       system-setup-keyboard = 0.9
Obsoletes:      nss-myhostname < 0.4
Provides:       nss-myhostname = 0.4
Obsoletes:      upstart < 1.2-3
Obsoletes:      upstart-sysvinit < 1.2-3
Conflicts:      upstart-sysvinit
Obsoletes:      hal
Obsoletes:      ConsoleKit

%description
systemd is a system and service manager for Linux, compatible with
SysV and LSB init scripts. systemd provides aggressive parallelization
capabilities, uses socket and D-Bus activation for starting services,
offers on-demand starting of daemons, keeps track of processes using
Linux cgroups, supports snapshotting and restoring of the system
state, maintains mount and automount points and implements an
elaborate transactional dependency-based service control logic. It can
work as a drop-in replacement for sysvinit.

%package libs
Summary:        systemd libraries
License:        LGPLv2+ and MIT
Obsoletes:      libudev < 183

%description libs
Libraries for systemd and udev, as well as the systemd PAM module.

%package devel
Summary:        Development headers for systemd
License:        LGPLv2+ and MIT
Requires:       %{name} = %{version}-%{release}
Provides:       libudev-devel = %{version}
Obsoletes:      libudev-devel < 183
Requires:       %{name}-libs = %{version}-%{release}

%description devel
Development headers and auxiliary files for developing applications for systemd.

%package sysv
Summary:        SysV tools for systemd
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release}

%description sysv
SysV compatibility tools for systemd

%package python
Summary:        Python 2 bindings for systemd
License:        LGPLv2+
Requires:       %{name} = %{version}-%{release}
Requires:       %{name}-libs = %{version}-%{release}

%description python
This package contains bindings which allow Python 2 programs to use
systemd APIs

%package -n libgudev1
Summary:        Libraries for adding libudev support to applications that use glib
Conflicts:      filesystem < 3
License:        LGPLv2+
Requires:       %{name}-libs = %{version}-%{release}
Requires:       glib2 >= 2.42

%description -n libgudev1
This package contains the libraries that make it easier to use libudev
functionality from applications that use glib.

%package -n libgudev1-devel
Summary:        Header files for adding libudev support to applications that use glib
Requires:       libgudev1 = %{version}-%{release}
License:        LGPLv2+

%description -n libgudev1-devel
This package contains the header and pkg-config files for developing
glib-based applications using libudev functionality.

%package journal-gateway
Summary:        Gateway for serving journal events over the network using HTTP
Requires:       %{name} = %{version}-%{release}
License:        LGPLv2+
Requires(pre):    /usr/bin/getent
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description journal-gateway
systemd-journal-gatewayd serves journal events over the network using HTTP.

%package networkd
Summary:        System service that manages networks.
Requires:       %{name} = %{version}-%{release}
License:        LGPLv2+
Requires(pre):    /usr/bin/getent
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description networkd
systemd-networkd is a system service that manages networks.
It detects and configures network devices as they appear, as well as creating virtual network devices.

%package resolved
Summary:        Network Name Resolution manager.
Requires:       %{name} = %{version}-%{release}
License:        LGPLv2+
Requires(pre):    /usr/bin/getent
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description resolved
systemd-resolved is a system service that manages network name resolution.
It implements a caching DNS stub resolver and an LLMNR resolver and responder.

%prep
%autosetup -p1
%{?_cov_prepare}

%build
./autogen.sh

CONFIGURE_OPTS=(
    --libexecdir=%{_prefix}/lib
    --with-sysvinit-path=/etc/rc.d/init.d
    --with-rc-local-script-path-start=/etc/rc.d/rc.local
    --disable-timesyncd
    --disable-kdbus
    --disable-terminal
    --enable-gtk-doc
    --enable-compat-libs
    --disable-sysusers
    --disable-ldconfig
    --enable-lz4
%ifarch s390 s390x ppc %{power64} aarch64
    --disable-lto
%endif
)

%configure "${CONFIGURE_OPTS[@]}"
%{?_cov_wrap} make %{?_smp_mflags} GCC_COLORS="" V=1

%install
%make_install

find %{buildroot} \( -name '*.a' -o -name '*.la' \) -delete
sed -i 's/L+/#/' %{buildroot}/usr/lib/tmpfiles.d/etc.conf

rm -f %{buildroot}%{_datadir}/polkit-1/actions/org.freedesktop.*.policy
install -m 0644 %{SOURCE7} %{buildroot}%{_datadir}/polkit-1/actions/
install -m 0644 %{SOURCE8} %{buildroot}%{_datadir}/polkit-1/actions/
install -m 0644 %{SOURCE9} %{buildroot}%{_datadir}/polkit-1/actions/
install -m 0644 %{SOURCE10} %{buildroot}%{_datadir}/polkit-1/actions/
install -m 0644 %{SOURCE11} %{buildroot}%{_datadir}/polkit-1/actions/
install -m 0644 %{SOURCE12} %{buildroot}%{_datadir}/polkit-1/actions/
install -m 0644 %{SOURCE13} %{buildroot}%{_datadir}/polkit-1/actions/

# udev links
mkdir -p %{buildroot}/%{_sbindir}
ln -sf ../bin/udevadm %{buildroot}%{_sbindir}/udevadm

# Create SysV compatibility symlinks. systemctl/systemd are smart
# enough to detect in which way they are called.
ln -s ../lib/systemd/systemd %{buildroot}%{_sbindir}/init
ln -s ../bin/systemctl %{buildroot}%{_sbindir}/reboot
ln -s ../bin/systemctl %{buildroot}%{_sbindir}/halt
ln -s ../bin/systemctl %{buildroot}%{_sbindir}/poweroff
ln -s ../bin/systemctl %{buildroot}%{_sbindir}/shutdown
ln -s ../bin/systemctl %{buildroot}%{_sbindir}/telinit
ln -s ../bin/systemctl %{buildroot}%{_sbindir}/runlevel

# legacy links
ln -s loginctl %{buildroot}%{_bindir}/systemd-loginctl
ln -s coredumpctl %{buildroot}%{_bindir}/systemd-coredumpctl

# We create all wants links manually at installation time to make sure
# they are not owned and hence overriden by rpm after the user deleted
# them.
rm -r %{buildroot}%{_sysconfdir}/systemd/system/*.target.wants

# Make sure the ghost-ing below works
touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel2.target
touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel3.target
touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel4.target
touch %{buildroot}%{_sysconfdir}/systemd/system/runlevel5.target

# Make sure these directories are properly owned
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/basic.target.wants
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/default.target.wants
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/dbus.target.wants
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/syslog.target.wants

# Temporary workaround for #1002806
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/poweroff.target.wants
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/rescue.target.wants
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/multi-user.target.wants
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/graphical.target.wants
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system/reboot.target.wants
ln -s ../systemd-update-utmp-runlevel.service %{buildroot}%{_prefix}/lib/systemd/system/poweroff.target.wants/
ln -s ../systemd-update-utmp-runlevel.service %{buildroot}%{_prefix}/lib/systemd/system/rescue.target.wants/
ln -s ../systemd-update-utmp-runlevel.service %{buildroot}%{_prefix}/lib/systemd/system/multi-user.target.wants/
ln -s ../systemd-update-utmp-runlevel.service %{buildroot}%{_prefix}/lib/systemd/system/graphical.target.wants/
ln -s ../systemd-update-utmp-runlevel.service %{buildroot}%{_prefix}/lib/systemd/system/reboot.target.wants/

mkdir -p %{buildroot}%{_localstatedir}/{run,log}/
touch %{buildroot}%{_localstatedir}/run/utmp
touch %{buildroot}%{_localstatedir}/log/{w,b}tmp

# Make sure the user generators dir exists too
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-generators
mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-generators

# Create new-style configuration files so that we can ghost-own them
touch %{buildroot}%{_sysconfdir}/hostname
touch %{buildroot}%{_sysconfdir}/vconsole.conf
touch %{buildroot}%{_sysconfdir}/locale.conf
touch %{buildroot}%{_sysconfdir}/machine-id
touch %{buildroot}%{_sysconfdir}/machine-info
touch %{buildroot}%{_sysconfdir}/localtime
mkdir -p %{buildroot}%{_sysconfdir}/X11/xorg.conf.d
touch %{buildroot}%{_sysconfdir}/X11/xorg.conf.d/00-keyboard.conf

# Install default preset policy
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-preset/
mkdir -p %{buildroot}%{_prefix}/lib/systemd/user-preset/
install -m 0644 %{SOURCE1} %{buildroot}%{_prefix}/lib/systemd/system-preset/

# Make sure the shutdown/sleep drop-in dirs exist
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-shutdown/
mkdir -p %{buildroot}%{_prefix}/lib/systemd/system-sleep/

# Make sure the NTP units dir exists
mkdir -p %{buildroot}%{_prefix}/lib/systemd/ntp-units.d/

# Make sure directories in /var exist
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/coredump
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/catalog
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/backlight
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/rfkill
mkdir -p %{buildroot}%{_localstatedir}/lib/systemd/journal-upload

touch %{buildroot}%{_localstatedir}/lib/systemd/catalog/database
touch %{buildroot}%{_sysconfdir}/udev/hwdb.bin
touch %{buildroot}%{_localstatedir}/lib/systemd/random-seed
touch %{buildroot}%{_localstatedir}/lib/systemd/clock


# Install SysV conversion tool for systemd
install -m 0755 %{SOURCE3} %{buildroot}%{_bindir}/

# Install yum protection fragment
mkdir -p %{buildroot}%{_sysconfdir}/yum/protected.d/
install -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/yum/protected.d/systemd.conf

# Install rc.local
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/
install -m 0644 %{SOURCE4} %{buildroot}%{_sysconfdir}/rc.d/rc.local
ln -s rc.d/rc.local %{buildroot}%{_sysconfdir}/rc.local

# Install rsyslog fragment
mkdir -p %{buildroot}%{_sysconfdir}/rsyslog.d/
install -m 0644 %{SOURCE6} %{buildroot}%{_sysconfdir}/rsyslog.d/

# Delete LICENSE files from _docdir (we'll get them in as %%license)
rm -rf %{buildroot}%{_docdir}/LICENSE*

# Install script and udev rule for adding phys_port_name for mlxsw and rocker drivers
# And put them in dracut
mkdir -p %{buildroot}%{_prefix}/lib/udev/rules.d
install -m 0755 %{SOURCE14} %{buildroot}%{_prefix}/lib/udev/
install -m 0644 %{SOURCE15} %{buildroot}%{_prefix}/lib/udev/rules.d/
mkdir -p %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d
install -m 0644 %{SOURCE16} %{buildroot}%{_prefix}/lib/dracut/dracut.conf.d/

%find_lang %{name}

# To avoid making life hard for Rawhide-using developers, don't package the
# kernel.core_pattern setting until systemd-coredump is a part of an actual
# systemd release and it's made clear how to get the core dumps out of the
# journal.
rm -f %{buildroot}%{_prefix}/lib/sysctl.d/50-coredump.conf

# For now remove /var/log/README since we are not enabling persistant
# logging yet.
rm -f %{buildroot}%{_localstatedir}/log/README

# No tmp-on-tmpfs by default in RHEL7. bz#876122
rm -f %{buildroot}%{_prefix}/lib/systemd/system/local-fs.target.wants/tmp.mount

# No gpt-auto-generator in RHEL7
rm -f %{buildroot}%{_prefix}/lib/systemd/system-generators/systemd-gpt-auto-generator

# 50-bridge.conf rules are in intscripts
rm -f %{buildroot}%{_prefix}/lib/sysctl.d/50-bridge.conf

# no networkd in rhel7
rm -f %{buildroot}%{_prefix}/lib/systemd/network/*

# no sysusers in rhel7
rm -f %{buildroot}%{_mandir}/man5/sysusers.d.5.gz
rm -f %{buildroot}%{_mandir}/man8/systemd-sysusers.*

install -m 0644 %{SOURCE5} $RPM_BUILD_ROOT/%{_udevrulesdir}/

%{?_cov_install}

%pre
getent group cdrom >/dev/null 2>&1 || groupadd -r -g 11 cdrom >/dev/null 2>&1 || :
getent group utmp >/dev/null 2>&1 || groupadd -r -g 22 utmp >/dev/null 2>&1 || :
getent group tape >/dev/null 2>&1 || groupadd -r -g 33 tape >/dev/null 2>&1 || :
getent group dialout >/dev/null 2>&1 || groupadd -r -g 18 dialout >/dev/null 2>&1 || :
getent group input >/dev/null 2>&1 || groupadd -r input >/dev/null 2>&1 || :
getent group floppy >/dev/null 2>&1 || groupadd -r -g 19 floppy >/dev/null 2>&1 || :
getent group systemd-journal >/dev/null 2>&1 || groupadd -r -g 190 systemd-journal 2>&1 || :
getent group systemd-network >/dev/null 2>&1 || groupadd -r -g 192 systemd-network 2>&1 || :
getent passwd systemd-network >/dev/null 2>&1 || useradd -r -u 192 -l -g systemd-network -d / -s /sbin/nologin -c "systemd Network Management" systemd-network >/dev/null 2>&1 || :

systemctl stop systemd-udevd-control.socket systemd-udevd-kernel.socket systemd-udevd.service >/dev/null 2>&1 || :

%post
systemd-machine-id-setup >/dev/null 2>&1 || :
/usr/lib/systemd/systemd-random-seed save >/dev/null 2>&1 || :
systemctl daemon-reexec >/dev/null 2>&1 || :
systemctl start systemd-udevd.service >/dev/null 2>&1 || :
udevadm hwdb --update >/dev/null 2>&1 || :
journalctl --update-catalog >/dev/null 2>&1 || :
systemd-tmpfiles --create >/dev/null 2>&1 || :

# Make sure new journal files will be owned by the "systemd-journal" group
chgrp systemd-journal /run/log/journal/ /run/log/journal/`cat /etc/machine-id 2> /dev/null` /var/log/journal/ /var/log/journal/`cat /etc/machine-id 2> /dev/null` >/dev/null 2>&1 || :
chmod g+s /run/log/journal/ /run/log/journal/`cat /etc/machine-id 2> /dev/null` /var/log/journal/ /var/log/journal/`cat /etc/machine-id 2> /dev/null` >/dev/null 2>&1 || :

if [ $1 -eq 1 ] ; then
    # Try to read default runlevel from the old inittab if it exists
    runlevel=$(awk -F ':' '$3 == "initdefault" && $1 !~ "^#" { print $2 }' /etc/inittab 2> /dev/null)
    if [ -z "$runlevel" ] ; then
        target="/usr/lib/systemd/system/graphical.target"
    else
        target="/usr/lib/systemd/system/runlevel$runlevel.target"
    fi

    # And symlink what we found to the new-style default.target
    ln -sf "$target" /etc/systemd/system/default.target >/dev/null 2>&1 || :

    # Services we install by default, and which are controlled by presets.
    systemctl preset \
        remote-fs.target \
        getty@.service \
        serial-getty@.service \
        console-getty.service \
        console-shell.service \
        debug-shell.service \
        systemd-readahead-replay.service \
        systemd-readahead-collect.service \
        >/dev/null 2>&1 || :
else
    # This systemd service does not exist anymore, we now do it
    # internally in PID 1
    rm -f /etc/systemd/system/sysinit.target.wants/hwclock-load.service >/dev/null 2>&1 || :

    # This systemd target does not exist anymore. It's been replaced
    # by ntp-units.d.
    rm -f /etc/systemd/system/multi-user.target.wants/systemd-timedated-ntp.target >/dev/null 2>&1 || :

    # Enable the units recorded by %%pretrans
    if [ -e /var/lib/rpm-state/systemd/ntp-units ] ; then
        while read service; do
            systemctl enable "$service" >/dev/null 2>&1 || :
        done < /var/lib/rpm-state/systemd/ntp-units
        rm -r /var/lib/rpm-state/systemd/ntp-units >/dev/null 2>&1 || :
    fi
fi

# Move old stuff around in /var/lib
mv %{_localstatedir}/lib/random-seed %{_localstatedir}/lib/systemd/random-seed >/dev/null 2>&1 || :
mv %{_localstatedir}/lib/backlight %{_localstatedir}/lib/systemd/backlight >/dev/null 2>&1 || :

# Migrate /etc/sysconfig/clock
if [ ! -L /etc/localtime -a -e /etc/sysconfig/clock ] ; then
    . /etc/sysconfig/clock >/dev/null 2>&1 || :
    if [ -n "$ZONE" -a -e "/usr/share/zoneinfo/$ZONE" ] ; then
        ln -sf "../usr/share/zoneinfo/$ZONE" /etc/localtime >/dev/null 2>&1 || :
    fi
fi
rm -f /etc/sysconfig/clock >/dev/null 2>&1 || :

# Migrate /etc/sysconfig/i18n
if [ -e /etc/sysconfig/i18n -a ! -e /etc/locale.conf ]; then
    unset LANG
    unset LC_CTYPE
    unset LC_NUMERIC
    unset LC_TIME
    unset LC_COLLATE
    unset LC_MONETARY
    unset LC_MESSAGES
    unset LC_PAPER
    unset LC_NAME
    unset LC_ADDRESS
    unset LC_TELEPHONE
    unset LC_MEASUREMENT
    unset LC_IDENTIFICATION
    . /etc/sysconfig/i18n >/dev/null 2>&1 || :
    [ -n "$LANG" ] && echo LANG=$LANG > /etc/locale.conf 2>&1 || :
    [ -n "$LC_CTYPE" ] && echo LC_CTYPE=$LC_CTYPE >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_NUMERIC" ] && echo LC_NUMERIC=$LC_NUMERIC >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_TIME" ] && echo LC_TIME=$LC_TIME >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_COLLATE" ] && echo LC_COLLATE=$LC_COLLATE >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_MONETARY" ] && echo LC_MONETARY=$LC_MONETARY >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_MESSAGES" ] && echo LC_MESSAGES=$LC_MESSAGES >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_PAPER" ] && echo LC_PAPER=$LC_PAPER >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_NAME" ] && echo LC_NAME=$LC_NAME >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_ADDRESS" ] && echo LC_ADDRESS=$LC_ADDRESS >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_TELEPHONE" ] && echo LC_TELEPHONE=$LC_TELEPHONE >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_MEASUREMENT" ] && echo LC_MEASUREMENT=$LC_MEASUREMENT >> /etc/locale.conf 2>&1 || :
    [ -n "$LC_IDENTIFICATION" ] && echo LC_IDENTIFICATION=$LC_IDENTIFICATION >> /etc/locale.conf 2>&1 || :
fi

# Migrate /etc/sysconfig/keyboard
if [ -e /etc/sysconfig/keyboard -a ! -e /etc/vconsole.conf ]; then
    unset SYSFONT
    unset SYSFONTACM
    unset UNIMAP
    unset KEYMAP
    [ -e /etc/sysconfig/i18n ] && . /etc/sysconfig/i18n >/dev/null 2>&1 || :
    . /etc/sysconfig/keyboard >/dev/null 2>&1 || :
    [ -n "$SYSFONT" ] && echo FONT=$SYSFONT > /etc/vconsole.conf 2>&1 || :
    [ -n "$SYSFONTACM" ] && echo FONT_MAP=$SYSFONTACM >> /etc/vconsole.conf 2>&1 || :
    [ -n "$UNIMAP" ] && echo FONT_UNIMAP=$UNIMAP >> /etc/vconsole.conf 2>&1 || :
    [ -n "$KEYTABLE" ] && echo KEYMAP=$KEYTABLE >> /etc/vconsole.conf 2>&1 || :
fi
rm -f /etc/sysconfig/i18n >/dev/null 2>&1 || :
rm -f /etc/sysconfig/keyboard >/dev/null 2>&1 || :

# Migrate HOSTNAME= from /etc/sysconfig/network
if [ -e /etc/sysconfig/network -a ! -e /etc/hostname ]; then
    unset HOSTNAME
    . /etc/sysconfig/network >/dev/null 2>&1 || :
    [ -n "$HOSTNAME" ] && echo $HOSTNAME > /etc/hostname 2>&1 || :
fi
sed -i '/^HOSTNAME=/d' /etc/sysconfig/network >/dev/null 2>&1 || :

# Migrate the old systemd-setup-keyboard X11 configuration fragment
if [ ! -e /etc/X11/xorg.conf.d/00-keyboard.conf ] ; then
    mv /etc/X11/xorg.conf.d/00-system-setup-keyboard.conf /etc/X11/xorg.conf.d/00-keyboard.conf >/dev/null 2>&1 || :
else
    rm -f /etc/X11/xorg.conf.d/00-system-setup-keyboard.conf >/dev/null 2>&1 || :
fi

# sed-fu to add myhostname to the hosts line of /etc/nsswitch.conf
# Only do that when installing, not when updating.
if [ $1 -eq 1 -a -f /etc/nsswitch.conf ] ; then
    sed -i.bak -e '
/^hosts:/ !b
/\<myhostname\>/ b
s/[[:blank:]]*$/ myhostname/
' /etc/nsswitch.conf >/dev/null 2>&1 || :
fi

%posttrans
# Convert old /etc/sysconfig/desktop settings
preferred=
if [ -f /etc/sysconfig/desktop ]; then
    . /etc/sysconfig/desktop
    if [ "$DISPLAYMANAGER" = GNOME ]; then
        preferred=gdm
    elif [ "$DISPLAYMANAGER" = KDE ]; then
        preferred=kdm
    elif [ "$DISPLAYMANAGER" = WDM ]; then
        preferred=wdm
    elif [ "$DISPLAYMANAGER" = XDM ]; then
        preferred=xdm
    elif [ -n "$DISPLAYMANAGER" ]; then
        preferred=${DISPLAYMANAGER##*/}
    fi
fi
if [ -z "$preferred" ]; then
    if [ -x /usr/sbin/gdm ]; then
        preferred=gdm
    elif [ -x /usr/bin/kdm ]; then
        preferred=kdm
    fi
fi
if [ $1 -eq 1 -a -n "$preferred" -a -r "/usr/lib/systemd/system/$preferred.service" ]; then
    # This is supposed to fail when the symlink already exists
    ln -s "/usr/lib/systemd/system/$preferred.service" /etc/systemd/system/display-manager.service >/dev/null 2>&1 || :
fi

%postun
if [ $1 -ge 1 ] ; then
    systemctl daemon-reload > /dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] ; then
    systemctl disable \
        remote-fs.target \
        getty@.service \
        serial-getty@.service \
        console-getty.service \
        console-shell.service \
        debug-shell.service \
        systemd-readahead-replay.service \
        systemd-readahead-collect.service \
        >/dev/null 2>&1 || :

    rm -f /etc/systemd/system/default.target >/dev/null 2>&1 || :

    if [ -f /etc/nsswitch.conf ] ; then
        sed -i.bak -e '
/^hosts:/ !b
s/[[:blank:]]\+myhostname\>//
' /etc/nsswitch.conf >/dev/null 2>&1 || :
    fi
fi

%post libs -p /sbin/ldconfig
%postun libs -p /sbin/ldconfig

%post -n libgudev1 -p /sbin/ldconfig
%postun -n libgudev1 -p /sbin/ldconfig

%pre journal-gateway
getent group systemd-journal-gateway >/dev/null 2>&1 || groupadd -r -g 191 systemd-journal-gateway 2>&1 || :
getent passwd systemd-journal-gateway >/dev/null 2>&1 || useradd -r -l -u 191 -g systemd-journal-gateway -d %{_localstatedir}/log/journal -s /sbin/nologin -c "Journal Gateway" systemd-journal-gateway >/dev/null 2>&1 || :
getent group systemd-journal-remote >/dev/null 2>&1 || groupadd -r systemd-journal-remote 2>&1 || :
getent passwd systemd-journal-remote >/dev/null 2>&1 || useradd -r -l -g systemd-journal-remote -d /%{_localstatedir}/log/journal/remote -s /sbin/nologin -c "Journal Remote" systemd-journal-remote >/dev/null 2>&1 || :
getent group systemd-journal >/dev/null 2>&1 || groupadd -r -g 190 systemd-journal 2>&1 || :
getent group systemd-journal-upload >/dev/null 2>&1 || groupadd -r systemd-journal-upload 2>&1 || :
getent passwd systemd-journal-upload >/dev/null 2>&1 || useradd -r -l -g systemd-journal-upload -G systemd-journal -d /%{_localstatedir}/log/journal/upload -s /sbin/nologin -c "Journal Upload" systemd-journal-upload >/dev/null 2>&1 || :

%post journal-gateway
%systemd_post systemd-journal-gatewayd.socket systemd-journal-gatewayd.service
%systemd_post systemd-journal-remote.socket systemd-journal-remote.service
%systemd_post systemd-journal-upload.service

%preun journal-gateway
%systemd_preun systemd-journal-gatewayd.socket systemd-journal-gatewayd.service
%systemd_preun systemd-journal-remote.socket systemd-journal-remote.service
%systemd_preun systemd-journal-upload.service

%postun journal-gateway
%systemd_postun_with_restart systemd-journal-gatewayd.service
%systemd_postun_with_restart systemd-journal-remote.service
%systemd_postun_with_restart systemd-journal-upload.service

%post networkd
%systemd_post systemd-networkd.service systemd-networkd-wait-online.service

%preun networkd
%systemd_preun systemd-networkd.service systemd-networkd-wait-online.service

%postun networkd
%systemd_postun_with_restart systemd-networkd.service systemd-networkd-wait-online.service

%pre resolved
getent group systemd-resolve >/dev/null 2>&1 || groupadd -r -g 193 systemd-resolve 2>&1 || :
getent passwd systemd-resolve >/dev/null 2>&1 || useradd -r -u 193 -l -g systemd-resolve -d / -s /sbin/nologin -c "systemd Resolver" systemd-resolve >/dev/null 2>&1 || :

%post resolved
%systemd_post systemd-resolved.service

%preun resolved
%systemd_preun systemd-resolved.service

%postun resolved
%systemd_postun_with_restart systemd-resolved.service

%triggerin -- systemd < 219-21
. /etc/sysconfig/network-scripts/network-functions

RULES_FILE="/etc/udev/rules.d/90-eno-fix.rules"
DRACUT_CONFIG="/etc/dracut.conf.d/90-eno-fix.conf"

NEED_REBUILD=
WROTE_MSG=

# systemd-219-30 refuses onboard indexes of network card bigger then 16383
# and this changes the name of the device. If we are updating on such machine
# let's keep the old name with udev rule
for i in /sys/class/net/eno* ; do
    DEVICE=${i##*/}

    [[ "$DEVICE" =~ eno[0-9]+(d[0-9]+)?$ ]] || continue
    [ "$(echo $DEVICE | sed -e 's/eno\([0-9]\+\).*/\1/')" -lt "16383" ] && continue

    HWADDR=$(get_hwaddr $DEVICE | tr '[:upper:]' '[:lower:]')
    [ -z "$HWADDR" ] && continue

    if [ -z "$WROTE_MSG" ]; then
       echo "# This file was automatically generated on systemd update" > "$RULES_FILE"
       WROTE_MSG=yes
    fi

    echo "SUBSYSTEM==\"net\", ACTION==\"add\", DRIVERS==\"?*\", ATTR{address}==\"$HWADDR\", NAME=\"$DEVICE\"" >> "$RULES_FILE"
    NEED_REBUILD=yes
done

if [ -n "$NEED_REBUILD" ]; then
    echo "install_items+=\" $RULES_FILE \"" > "$DRACUT_CONFIG"
    dracut -f
fi

%files -f %{name}.lang
%doc %{_docdir}/systemd
%{!?_licensedir:%global license %%doc}
%license LICENSE.GPL2 LICENSE.LGPL2.1 LICENSE.MIT
%dir %{_sysconfdir}/systemd
%dir %{_sysconfdir}/systemd/system
%dir %{_sysconfdir}/systemd/user
%dir %{_sysconfdir}/tmpfiles.d
%dir %{_sysconfdir}/sysctl.d
%dir %{_sysconfdir}/modules-load.d
%dir %{_sysconfdir}/binfmt.d
%dir %{_sysconfdir}/udev
%dir %{_sysconfdir}/udev/rules.d
%dir %{_prefix}/lib/systemd
%{_prefix}/lib/systemd/system-generators
%{_prefix}/lib/systemd/user-generators
%dir %{_prefix}/lib/systemd/system-preset
%dir %{_prefix}/lib/systemd/user-preset
%dir %{_prefix}/lib/systemd/system-shutdown
%dir %{_prefix}/lib/systemd/system-sleep
%dir %{_prefix}/lib/systemd/catalog
%dir %{_prefix}/lib/systemd/ntp-units.d
%dir %{_prefix}/lib/tmpfiles.d
%dir %{_prefix}/lib/sysctl.d
%dir %{_prefix}/lib/modules-load.d
%dir %{_prefix}/lib/binfmt.d
%dir %{_prefix}/lib/kernel
%dir %{_prefix}/lib/kernel/install.d
%dir %{_datadir}/systemd
%dir %{_datadir}/pkgconfig
%dir %{_datadir}/zsh
%dir %{_datadir}/zsh/site-functions
%ghost %dir %{_localstatedir}/log/journal
%dir %{_localstatedir}/lib/systemd
%dir %{_localstatedir}/lib/systemd/catalog
%ghost %dir %{_localstatedir}/lib/systemd/coredump
%ghost %dir %{_localstatedir}/lib/systemd/backlight
%ghost %dir %{_localstatedir}/lib/systemd/rfkill
%ghost %{_localstatedir}/lib/systemd/random-seed
%ghost %{_localstatedir}/lib/systemd/clock
%ghost %{_localstatedir}/lib/systemd/catalog/database
%ghost %attr(0664,root,utmp) %{_localstatedir}/run/utmp
%ghost %attr(0664,root,utmp) %{_localstatedir}/log/wtmp
%ghost %attr(0600,root,utmp) %{_localstatedir}/log/btmp
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.systemd1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.hostname1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.login1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.locale1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.timedate1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.machine1.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.import1.conf
%config(noreplace) %{_sysconfdir}/systemd/system.conf
%config(noreplace) %{_sysconfdir}/systemd/user.conf
%config(noreplace) %{_sysconfdir}/systemd/logind.conf
%config(noreplace) %{_sysconfdir}/systemd/journald.conf
%config(noreplace) %{_sysconfdir}/systemd/bootchart.conf
%config(noreplace) %{_sysconfdir}/systemd/coredump.conf
%config(noreplace) %{_sysconfdir}/udev/udev.conf
%config(noreplace) %{_sysconfdir}/rsyslog.d/listen.conf
%config(noreplace) %{_sysconfdir}/yum/protected.d/systemd.conf
%config(noreplace) %{_sysconfdir}/pam.d/systemd-user
%ghost %{_sysconfdir}/udev/hwdb.bin
%{_rpmconfigdir}/macros.d/macros.systemd
%{_sysconfdir}/xdg/systemd
%{_sysconfdir}/rc.d/init.d/README
%ghost %config(noreplace) %{_sysconfdir}/hostname
%ghost %config(noreplace) %{_sysconfdir}/localtime
%ghost %config(noreplace) %{_sysconfdir}/vconsole.conf
%ghost %config(noreplace) %{_sysconfdir}/locale.conf
%ghost %config(noreplace) %{_sysconfdir}/machine-id
%ghost %config(noreplace) %{_sysconfdir}/machine-info
%dir %{_sysconfdir}/X11/xorg.conf.d
%ghost %config(noreplace) %{_sysconfdir}/X11/xorg.conf.d/00-keyboard.conf
%{_bindir}/systemctl
%{_bindir}/systemd-notify
%{_bindir}/systemd-analyze
%{_bindir}/systemd-escape
%{_bindir}/systemd-ask-password
%{_bindir}/systemd-tty-ask-password-agent
%{_bindir}/systemd-machine-id-setup
%{_bindir}/loginctl
%{_bindir}/systemd-loginctl
%{_bindir}/journalctl
%{_bindir}/machinectl
%{_bindir}/busctl
%{_bindir}/coredumpctl
%{_bindir}/systemd-coredumpctl
%{_bindir}/systemd-tmpfiles
%{_bindir}/systemd-nspawn
%{_bindir}/systemd-stdio-bridge
%{_bindir}/systemd-cat
%{_bindir}/systemd-cgls
%{_bindir}/systemd-cgtop
%{_bindir}/systemd-delta
%{_bindir}/systemd-run
%{_bindir}/systemd-detect-virt
%{_bindir}/systemd-inhibit
%{_bindir}/systemd-path
%{_bindir}/systemd-firstboot
%{_bindir}/hostnamectl
%{_bindir}/localectl
%{_bindir}/timedatectl
%{_bindir}/bootctl
%{_bindir}/udevadm
%{_bindir}/kernel-install
%{_bindir}/systemd-hwdb
%{_prefix}/lib/systemd/systemd
%exclude %{_prefix}/lib/systemd/system/systemd-journal-gatewayd.*
%exclude %{_prefix}/lib/systemd/system/systemd-journal-remote.*
%exclude %{_prefix}/lib/systemd/system/systemd-journal-upload.*
%exclude %{_prefix}/lib/systemd/system/systemd-networkd*
%exclude %{_prefix}/lib/systemd/system/systemd-resolved.service
%exclude %{_prefix}/lib/systemd/system/dbus-org.freedesktop.resolve1.service
%exclude %{_prefix}/lib/systemd/system/dbus-org.freedesktop.network1.service
%{_prefix}/lib/systemd/system
%{_prefix}/lib/systemd/user
%exclude %{_prefix}/lib/systemd/systemd-journal-gatewayd
%exclude %{_prefix}/lib/systemd/systemd-journal-remote
%exclude %{_prefix}/lib/systemd/systemd-networkd
%exclude %{_prefix}/lib/systemd/systemd-networkd-wait-online
%exclude %{_prefix}/lib/systemd/systemd-resolved
%exclude %{_prefix}/lib/systemd/systemd-resolve-host
%exclude %{_prefix}/lib/systemd/systemd-journal-upload
%{_prefix}/lib/systemd/systemd-*
%{_prefix}/lib/systemd/import-pubring.gpg
%{_prefix}/lib/udev
%exclude  %{_sysconfdir}/udev/rules.d/80-net-setup-link.rules
%{_prefix}/lib/tmpfiles.d/systemd.conf
%{_prefix}/lib/tmpfiles.d/systemd-nologin.conf
%{_prefix}/lib/tmpfiles.d/x11.conf
%{_prefix}/lib/tmpfiles.d/legacy.conf
%{_prefix}/lib/tmpfiles.d/tmp.conf
%{_prefix}/lib/tmpfiles.d/var.conf
%{_prefix}/lib/tmpfiles.d/etc.conf
%{_prefix}/lib/tmpfiles.d/sap.conf
%{_prefix}/lib/sysctl.d/50-default.conf
%{_prefix}/lib/systemd/system-preset/90-systemd.preset
%{_prefix}/lib/systemd/system-preset/99-default-disable.preset
%{_prefix}/lib/systemd/catalog/systemd.catalog
%{_prefix}/lib/kernel/install.d/50-depmod.install
%{_prefix}/lib/kernel/install.d/90-loaderentry.install
%{_sbindir}/init
%{_sbindir}/reboot
%{_sbindir}/halt
%{_sbindir}/poweroff
%{_sbindir}/shutdown
%{_sbindir}/telinit
%{_sbindir}/runlevel
%{_sbindir}/udevadm
%{_mandir}/man1/*
%exclude %{_mandir}/man5/systemd.network.*
%exclude %{_mandir}/man5/systemd.netdev.*
%exclude %{_mandir}/man5/systemd.link.*
%exclude %{_mandir}/man5/resolved.conf.*
%{_mandir}/man5/*
%{_mandir}/man7/*
%exclude %{_mandir}/man8/systemd-journal-gatewayd.*
%exclude %{_mandir}/man8/systemd-journal-remote.*
%exclude %{_mandir}/man8/systemd-networkd*
%exclude %{_mandir}/man8/systemd-resolved.*
%{_mandir}/man8/*
%{_datadir}/systemd/kbd-model-map
%{_datadir}/dbus-1/services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.systemd1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.hostname1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.login1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.locale1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.timedate1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.machine1.service
%{_datadir}/dbus-1/system-services/org.freedesktop.import1.service
%dir %{_datadir}/polkit-1
%dir %{_datadir}/polkit-1/actions
%{_datadir}/polkit-1/actions/org.freedesktop.systemd1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.hostname1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.login1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.locale1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.timedate1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.machine1.policy
%{_datadir}/polkit-1/actions/org.freedesktop.import1.policy
%{_libdir}/pkgconfig/systemd.pc
%{_datadir}/pkgconfig/udev.pc
%{_datadir}/bash-completion/completions/*
%{_datadir}/zsh/site-functions/*
%{_prefix}/lib/systemd/catalog/systemd.*.catalog
%config(noreplace) %{_sysconfdir}/rc.d/rc.local
%{_sysconfdir}/rc.local
%{_datadir}/systemd/language-fallback-map
%{_prefix}/lib/dracut/dracut.conf.d/76-phys-port-name.conf

# Make sure we don't remove runlevel targets from F14 alpha installs,
# but make sure we don't create then anew.
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel2.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel3.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel4.target
%ghost %config(noreplace) %{_sysconfdir}/systemd/system/runlevel5.target

%files libs
%{_libdir}/security/pam_systemd.so
%{_libdir}/libnss_myhostname.so.2
%{_libdir}/libnss_mymachines.so.2
%{_libdir}/libudev.so.*
%{_libdir}/libsystemd.so.*
%{_libdir}/libsystemd-daemon.so.*
%{_libdir}/libsystemd-login.so.*
%{_libdir}/libsystemd-journal.so.*
%{_libdir}/libsystemd-id128.so.*

%files devel
%dir %{_includedir}/systemd
%{_libdir}/libudev.so
%{_libdir}/libsystemd.so
%{_libdir}/libsystemd-daemon.so
%{_libdir}/libsystemd-login.so
%{_libdir}/libsystemd-journal.so
%{_libdir}/libsystemd-id128.so
%{_includedir}/systemd/sd-daemon.h
%{_includedir}/systemd/sd-login.h
%{_includedir}/systemd/sd-journal.h
%{_includedir}/systemd/sd-id128.h
%{_includedir}/systemd/sd-messages.h
%{_includedir}/systemd/_sd-common.h
%{_includedir}/libudev.h
%{_libdir}/pkgconfig/libudev.pc
%{_libdir}/pkgconfig/libsystemd.pc
%{_libdir}/pkgconfig/libsystemd-daemon.pc
%{_libdir}/pkgconfig/libsystemd-login.pc
%{_libdir}/pkgconfig/libsystemd-journal.pc
%{_libdir}/pkgconfig/libsystemd-id128.pc
%{_mandir}/man3/*
%dir %{_datadir}/gtk-doc/html/libudev
%{_datadir}/gtk-doc/html/libudev/*

%files sysv
%{_bindir}/systemd-sysv-convert

%files python
%{python2_sitearch}/systemd

%files -n libgudev1
%{_libdir}/libgudev-1.0.so.*
%{_libdir}/girepository-1.0/GUdev-1.0.typelib

%files -n libgudev1-devel
%{_libdir}/libgudev-1.0.so
%dir %{_includedir}/gudev-1.0
%dir %{_includedir}/gudev-1.0/gudev
%{_includedir}/gudev-1.0/gudev/*.h
%{_datadir}/gir-1.0/GUdev-1.0.gir
%dir %{_datadir}/gtk-doc/html/gudev
%{_datadir}/gtk-doc/html/gudev/*
%{_libdir}/pkgconfig/gudev-1.0*

%files journal-gateway
%config(noreplace) %{_sysconfdir}/systemd/journal-remote.conf
%config(noreplace) %{_sysconfdir}/systemd/journal-upload.conf
%{_prefix}/lib/systemd/system/systemd-journal-gatewayd.*
%{_prefix}/lib/systemd/system/systemd-journal-remote.*
%{_prefix}/lib/systemd/system/systemd-journal-upload.*
%{_prefix}/lib/systemd/systemd-journal-gatewayd
%{_prefix}/lib/systemd/systemd-journal-upload
%{_prefix}/lib/systemd/systemd-journal-remote
%{_prefix}/lib/tmpfiles.d/systemd-remote.conf
%dir %attr(0755,systemd-journal-upload,systemd-journal-upload) %{_localstatedir}/lib/systemd/journal-upload
%{_mandir}/man8/systemd-journal-gatewayd.*
%{_mandir}/man8/systemd-journal-remote.*
%{_datadir}/systemd/gatewayd

%files networkd
%dir %{_prefix}/lib/systemd/network
%{_bindir}/networkctl
%{_prefix}/lib/systemd/system/systemd-networkd*
%{_prefix}/lib/systemd/systemd-networkd
%{_prefix}/lib/systemd/systemd-networkd-wait-online
%{_mandir}/man8/systemd-journal-gatewayd.*
%{_mandir}/man8/systemd-journal-remote.*
%{_mandir}/man8/systemd-networkd*
%{_mandir}/man5/systemd.network.*
%{_mandir}/man5/systemd.netdev.*
%{_mandir}/man5/systemd.link.*
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.network1.conf
%{_datadir}/dbus-1/system-services/org.freedesktop.network1.service
%{_prefix}/lib/udev/rules.d/80-net-setup-link.rules
%{_prefix}/lib/systemd/system/dbus-org.freedesktop.network1.service

%files resolved
%{_prefix}/lib/systemd/systemd-resolved
%{_prefix}/lib/systemd/systemd-resolve-host
%{_sysconfdir}/systemd/resolved.conf
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freedesktop.resolve1.conf
%{_datadir}/dbus-1/system-services/org.freedesktop.resolve1.service
%{_libdir}/libnss_resolve.so.2
%{_prefix}/lib/systemd/system/systemd-resolved.service
%{_prefix}/lib/systemd/system/dbus-org.freedesktop.resolve1.service
%{_mandir}/man5/resolved.conf.*
%{_mandir}/man8/systemd-resolved.*

%{?_cov_results_package}

%changelog
* Thu Mar 02 2023 Tim Smith <tim.smith@citrix.com> - 219-57.5
- CP-42030: Amend system requires

* Thu Oct 20 2022 Ross Lagerwall <ross.lagerwall@citrix.com> - 219-57.4
- CP-40192: Backport support for CPUQuotaPeriodSec

* Mon Feb 14 2022 Ross Lagerwall <ross.lagerwall@citrix.com> - 219-57.3
- Maintenance: fix guilt apply failure
- CA-334762: backport UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG
- CP-38416: Enable static analysis

* Fri Dec 04 2020 Ross Lagerwall <ross.lagerwall@citrix.com> - 219-57.2
- CA-349390: Backport missing udev patches from CentOS to fix a boot hang

* Mon Jun 25 2018 Lukas Nykryn <lnykryn@redhat.com> - 219-57.1
- umount: always use MNT_FORCE in umount_all() (#7213) (#1571098)
- core: Implement timeout based umount/remount limit (#1571098)
- core: Implement sync_with_progress() (#1571098)

* Tue Feb 20 2018 Lukas Nykryn <lnykryn@redhat.com> - 219-57
- sd-journal: properly handle inotify queue overflow (#1540538)
- sd-journal: make sure it's safe to call sd_journal_process() before the first sd_journal_wait() (#1540538)
- journalctl: Periodically call sd_journal_process in journalctl (#1540538)
- sd-journal: when picking up a new file, compare inode/device info with previous open file by same name (#1540538)

* Mon Feb 19 2018 Lukas Nykryn <lnykryn@redhat.com> - 219-56
- core: don't choke if a unit another unit triggers vanishes during reload (#1545676)

* Wed Feb 07 2018 Lukas Nykryn <lnykryn@redhat.com> - 219-55
- sparse: avoid clash with __bitwise and __force from 4.10 linux/types.h (#5061) (#1447937)
- core: Let two more booleans survive a daemon-reload (#1542391)

* Tue Feb 06 2018 Lukas Nykryn <lnykryn@redhat.com> - 219-54
- automount: ack automount requests even when already mounted (#1535135)
- udev: net_id add support for platform bus (ACPI, mostly arm64) devices (#1529633)
- journald-native: Fix typo in MANDLOCK message (#1501017)
- process-util: make our freeze() routine do something useful (#1540941)
- dbus: propagate errors from bus_init_system() and bus_init_api() (#1541061)
- bus-util.c: fix TasksMax= property assignment (#1537147)

* Tue Jan 09 2018 Lukas Nykryn <lnykryn@redhat.com> - 219-53
- shared/cgroup-utils: _CGROUP_CONTROLLER_MASK_ALL does not cover CGROUP_PIDS (#1532586)

* Thu Dec 14 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-52
- cryptsetup: when unlocking always put path to the object into Id (#1511043)
- cryptsetup: use more descriptive name for the variable and drop redundant function (#1511043)
- cryptsetup-generator: do not bind to the decrypted device unit (#6538) (#1511043)
- introduce naming based on phys_port_name for nfp via udev rule (#1516283)

* Tue Dec 05 2017 Lukáš Nykrýn <lnykryn@redhat.com> - 219-51
- revert substitute PACKAGE_STRING with the actual package NVR (#1453153)

* Mon Dec 04 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-50
- core: fix the reversed sanity check when setting StartupBlockIOWeight over dbus (#1302305)
- shared/dropin: ignore ENAMETOOLONG when checking drop-in directories (#7525) (#1489095)
- enable display manager only on systemd installation (#1464893)
- remove unnecessary dependency on dracut (#1466676)
- substitute PACKAGE_STRING with the actual package NVR (#1453153)

* Fri Nov 24 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-49
- journald: fix accuracy of watchdog timer event (#1511565)

* Thu Nov 23 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-48
- journald: never block when sending messages on NOTIFY_SOCKET socket (#1511565)
- journal: restore watchdog support (#1511565)
- cgroup resource property setting ignored if einval (rhbz#1302305)
- fileio: add new helper call read_line() as bounded getline() replacement (#1503106)
- def: add new constant LONG_LINE_MAX (#1503106)
- fileio: rework read_one_line_file() on top of read_line() (#1503106)
- cgroup-util: replace one use of fgets() by read_line() (#1503106)
- conf-parse: remove 4K line length limit (#1503106)
- test-conf-parser: add tests for config parser (#1503106)
- fileio: use _cleanup_ for FILE unlocking (#1503106)
- test-fileio: also test read_line() with actual files (#1503106)
- fileio: return 0 from read_one_line_file on success (#1503106)
- man: fix description of --force in halt(8) (#7392) (#1515130)
- journal: return better error for empty files (#1465759)
- journalctl: continue operation, even if we run into an invalid file (#1465759)
- journal: remove error check that never happens (#1465759)
- sd-journal: various clean-ups and modernizations (#1465759)
- journalctl: when we fail to open a journal file, print why (#1465759)

* Thu Nov 16 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-47
- cryptsetup-generator: use after free (#1477757)
- manager: fix connecting to bus when dbus is actually around (#7205) (#1465737)
- journal-remote: make --url option support arbitrary url (#1505385)
- journald: make maximum size of stream log lines configurable and bump it to 48K (#6838) (#1442262)
- service: serialize information about currently executing command (#1404657,#1471230)
- tests: add new test for issue #518 (#1404657,)
- tests: in RHEL-7 we don't have python3 by default (#1404657,)
- service: attempt to execute next main command only for oneshot services (#6619) (#1404657,)
- timedatectl: stop using xstrftime (#1503942)
- Add support to read lz4 compressed journals (rhbz#1431687)

* Tue Oct 31 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-46
- Support 'rdma' as a ListenNetlink= argument (#6626) (#1494610)
- core/namespace: Protect /usr instead of /home with ProtectSystem=yes (#1493047)
- udev: Use parent bus id for virtio disk builtin path-id (#5500) (#1496697)
- socket-util: socket_address_parse() should not log errors on its own (#1497639)
- test: fix failing test-socket-util when running with ipv6.disable=1 kernel param (#1497639)
- scsi_id: add missing options to getopt_long() (#6501) (#1476910)
- unmount: Pass in mount options when remounting read-only (#1312002)
- shutdown: don't remount,ro network filesystems. (#6588) (#1312002)
- shutdown: fix incorrect fscanf() result check (#6806) (#1312002)
- path-util: make use of "mnt_id" field exported in /proc/self/fdinfo/<fd> (#1472439)
- support ranges when parsing CPUAffinity (#1493976)
- man: Update man page documentation for CPUAffinity (#1493976)
- test-path-util: force rm_rf (#1472439)
- Export NVMe WWID udev attribute (#5348) (#1503253)
- mount: make sure we unmount tmpfs mounts before we deactivate swaps (#7076) (#1437518)
- journald: never accept fds from file systems with mandatory locking enabled (#1501017)
- udev: builtin-keyboard: move fetching the device node up (#1500119)
- udev: builtin-keyboard: immediately EVIOCSKEYCODE when we have a pair (#1500119)
- udev: builtin-keyboard: move actual key mapping to a helper function (#1500119)
- udev: builtin-keyboard: invert a condition (#1500119)
- udev: builtin-keyboard: add support for EVDEV_ABS_* (#1500119)
- hwdb: sync 60-evdev.hwdb from systemd v235 (rhbz#1500119)
- journal: ensure open journals from find_journal() (#3973) (#1493846)
- journal: only check available space when journal is open (#1493846)
- automount: if an automount unit is masked, don't react to activation anymore (#5445) (#1498318)
- units: add [Install] section to remote-cryptsetup.target (#1477757)
- units: replace remote-cryptsetup-pre.target with remote-fs-pre.target (#1477757)
- man: add a note about _netdev usage (#1477757)
- units: make remote-cryptsetup.target also after cryptsetup-pre.target (#1477757)

* Wed Sep 27 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-45
- journal: implicitly flush to var on recovery (#4028) (#1364092)
- journal: add/use flushed_flag_is_set() helper (#4041) (#1364092)
- journald: don't flush to /var/log/journal before we get asked to (#1364092)
- path-util: make use of "mnt_id" field exported in /proc/self/fdinfo/<fd> (#1472439)
- Revert "Revert "journald: allow restarting journald without losing stream connections"" (#1359939)
- journald: make sure we retain all stream fds across restarts (#6348) (#1359939)
- Allow systemd-tmpfiles to set the file/directory attributes (#1299714)
- tmpfiles: rework file attribute code (#1299714)
- tmpfiles: warn if we get an argument on lines that don't take any (#1299714)
- tmpfiles: substitute % specifiers in arguments for writing files and xattrs (#1299714)
- btrfs-util: introduce btrfs_is_filesystem() and make use of it where appropriate (#1299714)
- journal: don't force FS_NOCOW_FL on new journal files, but warn if it is missing (#1299714)
- tmpfiles: Add +C attrib to the journal files directories (#1299714)
- Revert "path-util: make use of "mnt_id" field exported in /proc/self/fdinfo/<fd>" (#1472439)
- device: make sure to remove all device units sharing the same sysfs path (#6679) (#1408916)
- manager: when reexecuting try to connect to bus only when dbus.service is around (#6773) (#1465737)
- doc: document service exit codes (#1178929)
- units: order cryptsetup-pre.target before cryptsetup.target (#1384014)
- man: add an explicit description of _netdev to systemd.mount(5) (#1384014)
- units: add remote-cryptsetup.target and remote-cryptsetup-pre.target (#1384014)
- cryptsetup-generator: use remote-cryptsetup.target when _netdev is present (#1384014)

* Tue Sep 12 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-44
- core: unset sysfs path after transition to dead state (#1408916)
- sysctl: fix uninitialized variable (#1485121)
- udev: ignore SIGCHLD from unexpected processes (#1306539) (#1306539)
- compile with -Werror (#1447937)
- myhostname: don't return any ipv6 entries when ipv6 is disabled (#1444824)
- core:execute: fix fork() fail handling in exec_spawn() (#1437114)
- fix compilation after commit 382877acc6c029e59e359a076d203ca03b4b9e9e (#1447937)
- Redefine 32bit time_t format to signed (#1447937)
- sd-bus/bus-kernel.c: fix format errors on ppc64le (#1447937)
- tmpfiles: with "e" don't attempt to set permissions when file doesn't exist (#1445732)
- units: introduce getty-pre.target (#6667) (#1173080)
- units: order container and console getty units after getty-pre.target (#1173080)
- log: never log into foreign fd #2 in PID 1 or its pre-execve() children (#1420505)
- nspawn: new option to start as PID2 (#1417387)

* Wed Aug 16 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-43
- tests: use XFS as root filesystem for system tests (#1475870)
- tests: use fdisk instead of sfdisk (#1475870)
- Revert "udev: net_id: add support for phys_port_name attribute (#4506)" (#1477285)
- reintroduce naming based on phys_port_name for mlxsw and rocker via udev rule

* Tue Jun 27 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-42
- Revert "rules: move cpu hotplug rule to separate file" (#1465108)

* Mon Jun 12 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-41
- rules: move cpu hotplug rule to separate file (#1266322)

* Tue May 30 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-40
- readahead-collect: don't print warning message when handling symlink (#1387095)
- tmpfiles: don't recursively descend into journal directories in /var (#1411199)
- tmpfiles: also set acls on /var/log/journal (#1411199)
- tmpfiles: set acls on system.journal explicitly (#1411199)
- sysctl: configure kernel parameters in the order they occur in each sysctl configuration files (#4205) (#1382244)
- units: drop explicit NotifyAccess setting from journald's unit file (#5749) (#1444356)
- systemd-notify: Always pass a valid pid to sd_pid_notify (#1381743)
- sd_pid_notify_with_fds: fix computing msg_controllen (#1381743)

* Tue May 02 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-39
- tests: set tasks_max to infinity (#1337244)
- Avoid forever loop for journalctl --list-boots command (#4278) (#1294516)
- sd-journal: return SD_JOURNAL_INVALIDATE only if journal files were actually deleted/moved (#5580) (#1446140)
- load-fragment: don't print error about incorrect syntax when IPv6 is disabled (#1377055)
- core: manager: add some missing dbus properties (#1427927)
- core: manager: expose DefaultLimit* as properties on dbus (#1427927)
- fstab-generator: remove bogus condition (#1446171)

* Thu Apr 20 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-38
- core: properly handle jobs that are suppressed to JOB_NOPs when propagating restarts (#1436021)

* Wed Apr 19 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-37
- core: add support for the "pids" cgroup controller (#1337244)
- core: add new DefaultTasksMax= setting for system.conf (#1337244)
- logind: add a new UserTasksMax= setting to logind.conf (#1337244)
- core: support percentage specifications on TasksMax= (#1337244)
- core: reinstate propagation of stop/restart jobs via RequsiteOf dependencies (#1436021)
- core: when propagating restart requests due to deps, downgrade restart to try-restart (#1436021)

* Thu Apr 13 2017 Lukáš Nykrýn <lnykryn@redhat.com> - 219-36
- spec cleanup (#1439787, #1392300, #1368929)

* Tue Apr 11 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-35
- tmpfiles: add new 'e' action which cleans up a dir without creating it (#1225739)
- util:bind_remount_recursive(): handle return 0 of set_consume() (#1433687)

* Tue Apr 11 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-34
- rules/40-redhat.rules: rules should be on one line (#1274401)

* Mon Apr 10 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-33
- execute: Add new PassEnvironment= directive (#1426214)
- test-execute: Add tests for new PassEnvironment= directive (#1426214)
- test-execute: Clarify interaction of PassEnvironment= and MANAGER_USER (#1426214)
- load-fragment: resolve specifiers in RuntimeDirectory (#1428110)
- Add microphone mute keymap for Dell Precision (#1413477)
- hwdb: update micmute YCODE on device node at DELL LATITUDE laptops for mic mute button. (#5012) (#1413477)
- udev/path_id: improve and enhance bus detection for Linux on z Systems (#1274401)
- core: port config_parse_bounding_set to extract_first_word (#1387398)
- core: simplify parsing of capability bounding set settings (#1387398)
- test: add test for capability bounding set parsing (#1387398)
- capabilities: keep bounding set in non-inverted format. (#1387398)
- capabilities: added support for ambient capabilities. (#1387398)
- man: add AmbientCapabilities entry. (#1387398)
- test-capability: rebase to upstream version (#1387398)
- namespace: don't fail on masked mounts (#1433687)
- sysv-generator: Provides: $network should also pull network.target to transaction (#5652) (#1438749)
- Install: correctly report symlink creations (#1435098)

* Mon Feb 20 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-32
- udev: fix crash with invalid udev.log-priority (#1245293)
- core: make exec code a bit more readable (#1421181)
- core: Private*/Protect* options with RootDirectory (#1421181)
- core: if the start command vanishes during runtime don't hit an assert (#1421658)
- systemctl: make sure that --now is carried out (#5209) (#1417459)
- udev: inform systemd how many workers we can potentially spawn (#4036) (#1361601)
- service: log_unit consumes id of unit not a unit (#1421658)
- automount: add expire support (#1354410)
- fstab-generator: fix memleak (#1354410)
- remove bus-proxyd (#1317518)

* Tue Feb 07 2017 Lukas Nykryn <lnykryn@redhat.com> - 219-31
- If the notification message length is 0, ignore the message (#4237) (#1380175)
- systemctl: suppress errors with "show" for nonexistent units and properties (#1380259)
- 40-redhat.rules: disable auto-online of hot-plugged memory on IBM z Systems (#1375603)
- pid1: don't return any error in manager_dispatch_notify_fd() (#4240) (#1380259)
- pid1: process zero-length notification messages again (#1380259
#1380259)
- pid1: more informative error message for ignored notifications (#1380259)
- manager: 219 needs u->id in log_unit_debug (#1380259)
- virt: add possibility to skip the check for chroot (#1379852)
- load-fragment: fix parsing values in bytes and prevent returning -ERANGE incorrectly (#1396277)
- core: fix assertion check (#1396312)
- tmp.mount.hm4: After swap.target (#3087) (#1298355)
- make sure all swap units are ordered before the swap target (#1298355)
- Recognise Lustre as a remote file system (#4530) (#1390542)
- unit: don't add Requires for tmp.mount (#1372249)
- core: return 0 from device_serialize() (#1403249)
- mtd_probe: include stdint (#1404251)
- tests: fix failure of test-execute if /dev/mem is not available (#5028) (#1410056)
- sd-journal: properly export has_{persistent|runtime}_files() (#1409527)
- core: add possibility to set action for ctrl-alt-del burst (#4105) (#1353028)
- failure-action: generalize failure action to emergency action (#1353028)
- core: use emergency_action for ctr+alt+del burst (#1353028)
- udev/path_id: introduce support for NVMe devices (#4169) (#1373150)
- core: fix CapabilityBoundingSet merging (#1409586)
- core: fix capability bounding set parsing (#1409586)
- core: make parsing of RLIMIT_NICE aware of actual nice levels (#1409588)
- shared: fix double free in unmask (#5005) (#1409997)
- shared: fix double free in link (#1409997)
- shared: check strdup != NULL (#1409997)
- core: improve error message when RefuseManualStart(Stop) is hit (#5132) (#1026648)
- systemctl: fix 'is-enabled' exit status on failure when executed in chroot (#4773) (#1413964)
- man: document that the automatic journal limits are capped to 4G by default (#1418547)
- random-seed: raise POOL_SIZE_MIN to 1024 (#1386824)
- bash-completion: add support for --now (#5155) (#1351806)
- basic: fix touch() creating files with 07777 mode (#1416062)
- udev: net_id: add support for phys_port_name attribute (#4506) (#1392426)
- install: introduce UnitFileFlags (#1413041)
- shared, systemctl: teach is-enabled to show installation targets (#1413041)

* Mon Nov 07 2016 Lukáš Nykrýn <lnykryn@redhat.com> - 219-30.6
- better version of vmware trigger

* Fri Nov  4 2016 Michal Sekletar <msekleta@redhat.com> - 219-30.5
- on update from systemd version 219-21 and older generate udev rules that preserve old network interface names on VMware VMs (#1391944)

* Thu Nov 03 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-30.4
- virt: add possibility to skip the check for chroot (#1379852)

* Fri Oct 07 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-30.3
- mtd_probe: add include for stdint (#1381573)

* Fri Oct 07 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-30.2
- manager: 219 needs u->id in log_unit_debug (#1381573)

* Wed Oct 05 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-30.1
- If the notification message length is 0, ignore the message (#4237) (#1381573)
- systemctl: suppress errors with "show" for nonexistent units and properties (#1380686)
- 40-redhat.rules: disable auto-online of hot-plugged memory on IBM z Systems (#1381123)
- pid1: don't return any error in manager_dispatch_notify_fd() (#4240) (#1381573)
- pid1: process zero-length notification messages again (#1381573)
- pid1: more informative error message for ignored notifications (#1381573)

* Tue Sep 13 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-30
- systemctl,pid1: do not warn about missing install info with "preset" (#1373950)
- systemctl/core: ignore masked units in preset-all (#1375097)
- shared/install: handle dangling aliases as an explicit case, report nicely (#1375097)
- shared/install: ignore unit symlinks when doing preset-all (#1375097)
- 40-redhat.rules: don't hoplug memory on s390x (#1370161)

* Mon Sep 05 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-29
- fix gcc warnings about uninitialized variables (#1318994)
- journalctl: rework code that checks whether we have access to /var/log/journal (#1318994)
- journalctl: Improve boot ID lookup (#1318994)
- journalctl: only have a single exit path from main() (#1318994)
- journalctl: free all command line argument objects (#1318994)
- journalctl: rename boot_id_t to BootId (#1318994)
- util: introduce CMSG_FOREACH() macro and make use of it everywhere (#1318994)
- journald: don't employ inner loop for reading from incoming sockets (#1318994)
- journald: fix count of object meta fields (#1318994)
- journal-cat: return a correct error, not -1 (#1318994)
- journalctl: introduce short options for --since and --until (#1318994)
- journal: s/Envalid/Invalid/ (#1318994)
- journald: dispatch SIGTERM/SIGINT with a low priority (#1318994)
- lz4: fix size check which had no chance of working on big-endian (#1318994)
- journal: normalize priority of logging sources (#1318994)
- Fix miscalculated buffer size and uses of size-unlimited sprintf() function. (#1318994)
- journal: Drop monotonicity check when appending to journal file (#1318994)
- journalctl: unify how we free boot id lists a bit (#1318994)
- journalctl: don't trust the per-field entry tables when looking for boot IDs (#1318994)
- units: remove udev control socket when systemd stops the socket unit (#49) (#1370133)
- logind: don't assert if the slice is missing (#1371437)
- core: enable transient unit support for slice units (#1370299)
- sd-bus: bump message queue size (#1371205)
- install: fix disable when /etc/systemd/system is a symlink (#1285996)
- rules: add NVMe rules (#3136) (#1274651)
- rules: introduce disk/by-id (model_serial) symlinks for NVMe drives (#3974) (#1274651)
- rules: fix for possible whitespace in the "model" attribute (#1274651)

* Fri Aug 19 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-27
- tmpfiles: enforce ordering when executing lines (#1365870)
- Introduce bus_unit_check_load_state() helper (#1256858)
- core: use bus_unit_check_load_state() in transaction_add_job_and_dependencies() (#1256858)
- udev/path_id: correct segmentation fault due to missing NULL check (#1365556)
- rules: load sg driver also when scsi_target appears (#45) (#1322773)

* Tue Aug 09 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-26
- install: do not crash when processing empty (masked) unit file (#1159308)
- Revert "install: fix disable via unit file path" (#1348208)
- systemctl: allow disable on the unit file path, but warn about it (#3806) (#1348208)

* Thu Aug 04 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-25
- units: increase watchdog timeout to 3min for all our services (#1267707)
- core: bump net.unix.max_dgram_qlen really early during boot (#1267707)
- core: fix priority ordering in notify-handling (#1267707)
- tests: fix personality tests on ppc64 and aarch64 (#1361049)
- systemctl: consider service running only when it is in active or reloading state (#3874) (#1362461)

* Mon Jul 18 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-24
- manager: don't skip sigchld handler for main and control pid for services (#3738) (#1342173)

* Tue Jul 12 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-23
- udevadm: explicitly relabel /etc/udev/hwdb.bin after rename (#1350756)
- systemctl: return diffrent error code if service exist or not (#3385) (#1047466)
- systemctl: Replace init script error codes with enum (#3400) (#1047466)
- systemctl: rework "systemctl status" a bit (#1047466)
- journal-verify: don't hit SIGFPE when determining progress (#1350232)
- journal: avoid mapping empty data and field hash tables (#1350232)
- journal: when verifying journal files, handle empty ones nicely (#1350232)
- journal: explain the error when we find a non-DATA object that is compressed (#1350232)
- journalctl: properly detect empty journal files (#1350232)
- journal: uppercase first character in verify error messages (#1350232)
- journalctl: make sure 'journalctl -f -t unmatched' blocks (#1350232)
- journalctl: don't print -- No entries -- in quiet mode (#1350232)
- sd-event: expose the event loop iteration counter via sd_event_get_iteration() (#1342173)
- manager: Only invoke a single sigchld per unit within a cleanup cycle (#1342173)
- manager: Fixing a debug printf formatting mistake (#1342173)
- core: support IEC suffixes for RLIMIT stuff (#1351415)
- core: accept time units for time-based resource limits (#1351415)
- time-util: add parse_time(), which is like parse_sec() but allows specification of default time unit if none is specified (#1351415)
- core: support <soft:hard> ranges for RLIMIT options (#1351415)
- core: fix rlimit parsing (#1351415)
- core: dump rlim_cur too (#1351415)
- install: fix disable via unit file path (#1348208)

* Wed Jun 22 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-22
- nspawn: when connected to pipes for stdin/stdout, pass them as-is to PID 1 (#1307080)
- mount: remove obsolete -n (#1339721)
- core: don't log job status message in case job was effectively NOP (#3199) (#1280014)
- core: use an AF_UNIX/SOCK_DGRAM socket for cgroup agent notification (#1305608)
- logind: process session/inhibitor fds at higher priority (#1305608)
- Teach bus_append_unit_property_assignment() about 'Delegate' property (#1337922)
- sd-netlink: fix deep recursion in message destruction (#1330593)
- add REMOTE_ADDR and REMOTE_PORT for Accept=yes (#1341154)
- core: don't dispatch load queue when setting Slice= for transient units (#1343904)
- run: make --slice= work in conjunction with --scope (#1343904)
- myhostname: fix timeout if ipv6 is disabled (#1330973)
- readahead: do not increase nr_requests for root fs block device (#1314559)
- manager: reduce complexity of unit_gc_sweep (#3507) (#1344556)
- hwdb: selinuxify a bit (#3460) (#1343648)

* Mon May 23 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-21
- path_id: reintroduce by-path links for virtio block devices (#952567)
- journal: fix error handling when compressing journal objects (#1292447)
- journal: irrelevant coding style fixes (#1292447)
- install: follow unit file symlinks in /usr, but not /etc when looking for [Install] data (#1159308)
- core: look for instance when processing template name (#1159308)
- core: improve error message when starting template without instance (#1142369)
- man/tmpfiles.d: add note about permissions and ownership of symlinks (#1296288)
- tmpfiles: don't follow symlinks when adjusting ACLs, fille attributes, access modes or ownership (#1296288)
- udev: filter out non-sensically high onboard indexes reported by the kernel (#1230210)
- test-execute: add tests for RuntimeDirectory (#1324826)
- core: fix group ownership when Group is set (#1324826)
- fstab-generator: cescape device name in root-fsck service (#1306126)
- core: add new RandomSec= setting for time units (#1305279)
- core: rename Random* to RandomizedDelay* (#1305279)
- journal-remote: change owner of /var/log/journal/remote and create /var/lib/systemd/journal-upload (#1327303)
- Add Seal option in the configuration file for journald-remote (#1329233)
- tests: fix make check failure (#1159308)
- device: make sure to not ignore re-plugged device (#1332606)
- device: Ensure we have sysfs path before comparing. (#1332606)
- core: fix memory leak on set-default, enable, disable etc (#1331667)
- nspawn: fix minor memory leak (#1331667)
- basic: fix error/memleak in socket-util (#1331667)
- core: fix memory leak in manager_run_generators() (#1331667)
- modules-load: fix memory leak (#1331667)
- core: fix memory leak on failed preset-all (#1331667)
- sd-bus: fix memory leak in test-bus-chat (#1331667)
- core: fix memory leak in transient units (#1331667)
- bus: fix leak in error path (#1331667)
- shared/logs-show: fix memleak in add_matches_for_unit (#1331667)
- logind: introduce LockedHint and SetLockedHint (#3238) (#1335499)
- import: use the old curl api (#1284974)
- importd: drop dkr support (#1284974)
- import: add support for gpg2 for verifying imported images (#1284974)

* Thu Mar 10 2016 Lukas Nykryn <lnykryn@redhat.com> - 219-20
- run: synchronously wait until the scope unit we create is started (#1272368)
- device: rework how we enter tentative state (#1283579)
- core: Do not bind a mount unit to a device, if it was from mountinfo (#1283579)
- logind: set RemoveIPC=no by default (#1284588)
- sysv-generator: follow symlinks in /etc/rc.d/init.d (#1285492)
- sysv-generator test: always log to console (#1279034)
- man: RemoveIPC is set to no on rhel (#1284588)
- Avoid /tmp being mounted as tmpfs without the user's will (#1298109)
- test sysv-generator: Check for network-online.target. (#1279034)
- arm/aarch64: detect-virt: check dmi (#1278165)
- detect-virt: dmi: look for KVM (#1278165)
- Revert "journald: turn ForwardToSyslog= off by default" (#1285642)
- terminal-util: when resetting terminals, don't wait for carrier (#1266745)
- basic/terminal-util: introduce SYSTEMD_COLORS environment variable (#1247963)
- ask-password: don't abort when message is missing (#1261136)
- sysv-generator: do not join dependencies on one line, split them (#1288600)
- udev: fibre channel: fix NPIV support (#1266934)
- ata_id: unreverse WWN identifier (#1273306)
- Fixup WWN bytes for big-endian systems (#1273306)
- sd-journal: introduce has_runtime_files and has_persistent_files (#1082179)
- journalctl: improve error messages when the specified boot is not found (#1082179)
- journalctl: show friendly info when using -b on runtime journal only (#1082179)
- journalctl: make "journalctl /dev/sda" work (#947636)
- journalctl: add match for the current boot when called with devpath (#947636)
- man: clarify what happens when journalctl is called with devpath (#947636)
- core: downgrade warning about duplicate device names (#1296249)
- udev: downgrade a few warnings to debug messages (#1289461)
- man: LEVEL in systemd-analyze set-log level is not optional (#1268336)
- Revert "udev: fibre channel: fix NPIV support" (#1266934)
- udev: path-id: fibre channel NPIV - use fc_vport's port_name (#1266934)
- systemctl: is-active/failed should return 0 if at least one unit is in given state (#1254650)
- rules: set SYSTEMD_READY=0 on DM_UDEV_DISABLE_OTHER_RULES_FLAG=1 only with ADD event (#1312011)
- s390: add personality support (#1300344)
- socket_address_listen - do not rely on errno (#1316452)

* Mon Oct 12 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-19
- udev: make naming for virtio devices opt-in (#1269216)
- tmpfiles.d: don't clean SAP sockets either (#1186044)

* Tue Oct 06 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-18
- tmpfiles.d: don't clean SAP lockfiles and logs (#1186044)

* Mon Sep 28 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-17
- sd-event: fix prepare priority queue comparison function (#1266479)
- units: run ldconfig also when cache is unpopulated (#1265539)
- selinux: fix regression of systemctl subcommands when absolute unit file paths are specified (#1185120)

* Wed Sep 23 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-16
- login: fix gcc warning, include missing header file (#1264073)
- shutdown: make sure /run/nologin has correct label (#1264073)

* Tue Sep 22 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-15
- login: fix label on /run/nologin (#1264073)
- udev-rules: prandom character device node permissions (#1264112)

* Tue Sep 15 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-14
- Revert "sysctl.d: default to fq_codel, fight bufferbloat" (#1263158)
- loginctl: print nontrivial properties in logictl show-* (#1260465)

* Wed Sep 02 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-13
- udev: net_id - support predictable ifnames on virtio buses (#1259015)

* Tue Sep 01 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-12
- selinux: fix check for transient units (#1255129)
- socket: fix setsockopt call. SOL_SOCKET changed to SOL_TCP. (#1135599)
- selinux: fix missing SELinux unit access check (#1185120)
- selinux: always use *_raw API from libselinux (#1256888)

* Wed Aug 12 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-11
- journald-server: don't read audit events (#1252409)
- everything: remove traces of --user (#1071363)

* Fri Aug 07 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-10
- Revert "journald: move /dev/log socket to /run" (#1249968)

* Fri Jul 31 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-9
- units: add [Install] section to tmp.mount
- bus-util: add articles to explanation messages (#1016680)
- bus-util: print correct warnings for units that fail but for which we have a NULL result only (#1016680)

* Thu Jul 16 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-8
- sysv-generator test: Fix assertion (#1222517)
- man: avoid line break in url (#1222517)
- Add VARIANT as a standard value for /etc/os-release (#1222517)
- Fix permissions on /run/systemd/nspawn/locks (#1222517)
- generators: rename add_{root,usr}_mount to add_{sysroot,sysroot_usr}_mount (#1222517)
- Generate systemd-fsck-root.service in the initramfs (#1222517)
- units: fix typo in systemd-resolved.service (#1222517)
- core: don't consider umask for SocketMode= (#1222517)
- timedate: fix memory leak in timedated (#1222517)
- coredump: make sure we vacuum by default (#1222517)
- tmpfiles: don't fail if we cannot create a subvolume because a file system is read-only but a dir already exists anyway (#1222517)
- resolved: fix crash when shutting down (#1222517)
- resolved: allow DnsAnswer objects with no space for RRs (#1222517)
- id128: add new sd_id128_is_null() call (#1222517)
- journalctl: Improve boot ID lookup (#1222517)
- test-hashmap: fix an assert (#1222517)
- units: make sure systemd-nspawn@.slice instances are actually located in machine.slice (#1222517)
- Revert "journald-audit: exit gracefully in the case we can't join audit multicast group" (#1222517)
- journald: handle more gracefully when bind() fails on audit sockets (#1222517)
- udev: link-config - fix corruption (#1222517)
- udev/net_id: Only read the first 64 bytes of PCI config space (#1222517)
- shared: generator - correct path to systemd-fsck (#1222517)
- logind: Save the user’s state when a session enters SESSION_ACTIVE (#1222517)
- small fix ru translation (#1222517)
- kmod-setup: don't warn when ipv6 can't be loaded (#1222517)
- Partially revert "ma-setup: simplify" (#1222517)
- ima-setup: write policy one line at a time (#1222517)
- ata_id: unbotch format specifier (#1222517)
- install: explicitly return 0 on success (#1222517)
- systemd.service.xml: document that systemd removes the PIDFile (#1222517)
- core: handle --log-target=null when calling systemd-shutdown (#1222517)
- man: ProtectHome= protects /root as well (#1222517)
- timedatectl: trim non-local RTC warning to 80 chars wide (#1222517)
- escape: fix exit code (#1222517)
- man: information about available properties (#1222517)
- journal: in persistent mode create /var/log/journal, with all parents. (#1222517)
- sysv-generator: fix wrong "Overwriting existing symlink" warnings (#1222517)
- mount: don't claim a device is gone from /proc/self/mountinfo before it is gone from *all* lines (#1222517)
- mount: properly check for mounts currently in /proc/self/mountinfo (#1222517)

* Tue Jul 14 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-7
- udev: fix crash in path_id builtin (#957112)

* Fri Jul 10 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-6
- sd-bus: don't inherit connection creds into message creds when we have a direct connection (#1230190)

* Tue Jun 30 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-5
- Revert "core: one step back again, for nspawn we actually can't wait for cgroups running empty since systemd will get exactly zero notifications about it" (#1199644)
- bus-creds: always set SD_BUS_CREDS_PID when we set pid in the mask (#1230190)
- sd-bus: do not use per-datagram auxiliary information (#1230190)
- sd-bus: store selinux context at connection time (#1230190)
- journald: simplify context handling (#1230190)
- bash-completion: add verb set-property (#1235635)

* Fri Jun 19 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-4
- core: Fix assertion with empty Exec*= paths (#1222517)
- rules: load sg module (#1186462)
- util: add shell_maybe_quote() call for preparing a string for shell cmdline inclusion (#1016680)
- bus-util: be more verbose if dbus job fails (#1016680)
- notify: fix badly backported help message (#1199644)
- cryptsetup: craft a unique ID with the source device (#1226333)
- systemctl: introduce --now for enable, disable and mask (#1233081)
- udev: also create old sas paths (#957112)
- journald: do not strip leading whitespace from messages (#1227396)

* Mon May 18 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-3
- console-getty.service: don't start when /dev/console is missing (#1222517)
- resolved: Do not add .busname dependencies, when compiling without kdbus. (#1222517)
- man: add journal-remote.conf(5) (#1222517)
- mount: don't run quotaon only for network filesystems (#1222517)
- mount: fix up wording in the comment (#1222517)
- udev: net_id - fix copy-paste error (#1222517)
- man: don't mention "journalctl /dev/sda" (#1222517)
- units: move After=systemd-hwdb-update.service dependency from udev to udev-trigger (#1222517)
- units: explicitly order systemd-user-sessions.service after nss-user-lookup.target (#1222517)
- zsh-completion: update loginctl (#1222517)
- zsh-completion: add missing -M completion for journalctl (#1222517)
- zsh-completion: update hostnamectl (#1222517)
- shell-completion: systemctl switch-root verb (#1222517)
- core/automount: beef up error message (#1222517)
- man: remove 'fs' from 'rootfsflags' (#1222517)
- shared: fix memleak (#1222517)
- udevd: fix synchronization with settle when handling inotify events (#1222517)
- python-systemd: fix is_socket_inet to cope with ports (#1222517)
- man: fix examples indentation in tmpfiles.d(5) (#1222517)
- systemctl: avoid bumping NOFILE rlimit unless needed (#1222517)
- exit-status: Fix "NOTINSSTALLED" typo (#1222517)
- tmpfiles: there's no systemd-forbid-user-logins.service service (#1222517)
- kmod-setup: load ip_tables kmod at boot (#1222517)
- util: Fix assertion in split() on missing ' (#1222517)
- units: set KillMode=mixed for our daemons that fork worker processes (#1222517)
- unit: don't add automatic dependencies on device units if they aren't supported (#1222517)
- update-done: ignore nanosecond file timestamp components, they are not reliable (#1222517)
- sd-daemon: simplify sd_pid_notify_with_fds (#1222517)
- fstab-generator: add x-systemd.requires and x-systemd.requires-mounts-for (#1164334)

* Thu May 14 2015 Lukas Nykryn <lnykryn@redhat.com> - 219-2
- udev: restore udevadm settle timeout (#1210981)
- udev: settle should return immediately when timeout is 0 (#1210981)
- udev: Fix ping timeout when settle timeout is 0 (#1210981)
- detect-virt: use /proc/device-tree (#1207773)
- ARM: detect-virt: detect Xen (#1207773)
- ARM: detect-virt: detect QEMU/KVM (#1207773)
- Persistent by_path links for ata devices (#1045498)
- man: document forwarding to syslog better (#1177336)
- man: fix typos in previous comimt (#1177336)
- LSB: always add network-online.target to services with priority over 10 (#1189253)
- rules: enable memory hotplug (#1105020)
- rules: reload sysctl settings when the bridge module is loaded (#1182105)

* Tue Apr 14 2015 Lukáš Nykrýn <lnykryn@redhat.com> - 219-1
- workaround build issues on ppc and s390
- some more patches

* Tue Mar 17 2015 Lukáš Nykrýn <lnykryn@redhat.com> - 219-0.4
- steal more patches from fedora

* Fri Mar 13 2015 Lukáš Nykrýn <lnykryn@redhat.com> - 219-0.3
- steal patches from fedora

* Fri Mar 06 2015 Lukáš Nykrýn <lnykryn@redhat.com> - 219-0.1
- rebase to 219

* Mon Dec 15 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 218-0.3
- rebase to 218
- remove networkd tmpfiles snipets due to packaging issues
- add resolved subpackage
- backport some nspawn features from upstream

* Thu Nov 20 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 217-0.3
- split systemd and networkd tmpfiles snippets

* Thu Nov 20 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 217-0.2
- spec fixes
- core: introduce new Delegate=yes/no property controlling creation of cgroup subhierarchies

* Mon Nov 17 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 217-0.1
- rebase to 217

* Mon Nov 10 2014 Lukas Nykryn <lnykryn@redhat.com> - 208-19
- cgroups-agent: really down-grade log level (#1044386)

* Mon Nov 10 2014 Lukas Nykryn <lnykryn@redhat.com> - 208-18
- login: rerun vconsole-setup when switching from vgacon to fbcon (#1002450)

* Fri Nov 07 2014 Lukas Nykryn <lnykryn@redhat.com> - 208-17
- udev: net_id dev_port is base 10 (#1155996)
- udev: Fix parsing of udev.event-timeout kernel parameter (#1154778)

* Thu Oct 30 2014 Lukas Nykryn <lnykryn@redhat.com> - 208-16
- logind: use correct "who" enum values with KillUnit. (#1155502)
- logind: always kill session when termination is requested (#1155502)
- udev: net_id - correctly name netdevs based on dev_port when set (#1155996)

* Tue Oct 21 2014 Lukas Nykryn <lnykryn@redhat.com> - 208-15
- core: do not segfault if /proc/swaps cannot be opened (#1151239)
- man: we don't have 'Wanted' dependency (#1152487)
- environment: append unit_id to error messages regarding EnvironmentFile (#1147691)
- udevd: add --event-timeout commandline option (#1154778)

* Wed Oct 08 2014 Lukas Nykryn <lnykryn@redhat.com> - 208-14
- core: don't allow enabling if unit is masked (#1149299)

* Tue Oct 07 2014 Lukas Nykryn <lnykryn@redhat.com> - 208-13
- tmpfiles: minor modernizations (#1147524)
- install: when looking for a unit file for enabling, search for templates only after traversing all search directories (#1147524)
- install: remove unused variable (#1147524)
- bootctl: typo fix in help message (#1147524)
- logind: ignore failing close() on session-devices (#1147524)
- sysfs-show.c: return negative error (#1147524)
- core: only send SIGHUP when doing first kill, not when doing final sigkill (#1147524)
- cgroup: make sure to properly send SIGCONT to all processes of a cgroup if that's requested (#1147524)
- core: don't send duplicate SIGCONT when killing units (#1147524)
- efi: fix Undefined reference efi_loader_get_boot_usec when EFI support is disabled (#1147524)
- macro: better make IN_SET() macro use const arrays (#1147524)
- macro: make sure we can use IN_SET() also with complex function calls as first argument (#1147524)
- core: fix property changes in transient units (#1147524)
- load-modules: properly return a failing error code if some module fails to load (#1147524)
- core/unit: fix unit_add_target_dependencies() for units with no dependencies (#1147524)
- man: there is no ExecStopPre= for service units (#1147524)
- man: document that per-interface sysctl variables are applied as network interfaces show up (#1147524)
- journal: downgrade vaccuum message to debug level (#1147524)
- logs-show: fix corrupt output with empty messages (#1147524)
- journalctl: refuse extra arguments with --verify and similar (#1147524)
- journal: assume that next entry is after previous entry (#1147524)
- journal: forget file after encountering an error (#1147524)
- man: update link to LSB (#1147524)
- man: systemd-bootchart - fix spacing in command (#1147524)
- man: add missing comma (#1147524)
- units: Do not unescape instance name in systemd-backlight@.service (#1147524)
- manager: flush memory stream before using the buffer (#1147524)
- man: multiple sleep modes are to be separated by whitespace, not commas (#1147524)
- man: fix description of systemctl --after/--before (#1147524)
- udev: properly detect reference to unexisting part of PROGRAM's result (#1147524)
- gpt-auto-generator: don't return OOM on parentless devices (#1147524)
- man: improve wording of systemctl's --after/--before (#1147524)
- cgroup: it's not OK to invoke alloca() in loops (#1147524)
- core: don't try to relabel mounts before we loaded the policy (#1147524)
- systemctl: --kill-mode is long long gone, don't mention it in the man page (#1147524)
- ask-password: when the user types a overly long password, beep and refuse (#1147524)
- logind: don't print error if devices vanish during ACL-init (#1147524)
- tty-ask-password-agent: return negative errno (#1147524)
- journal: cleanup up error handling in update_catalog() (#1147524)
- bash completion: fix __get_startable_units (#1147524)
- core: check the right variable for failed open() (#1147524)
- man: sd_journal_send does nothing when journald is not available (#1147524)
- man: clarify that the ExecReload= command should be synchronous (#1147524)
- conf-parser: never consider it an error if we cannot load a drop-in file because it is missing (#1147524)
- socket: properly handle if our service vanished during runtime (#1147524)
- Do not unescape unit names in [Install] section (#1147524)
- util: ignore_file should not allow files ending with '~' (#1147524)
- core: fix invalid free() in killall() (#1147524)
- install: fix invalid free() in unit_file_mask() (#1147524)
- unit-name: fix detection of unit templates/instances (#1147524)
- journald: make MaxFileSec really default to 1month (#1147524)
- bootchart: it's not OK to return -1 from a main program (#1147524)
- journald: Fix off-by-one error in "Missed X kernel messages" warning (#1147524)
- man: drop references to removed and obsolete 'systemctl load' command (#1147524)
- units: fix BindsTo= logic when applied relative to services with Type=oneshot (#1147524)

* Mon Sep 29 2014 Lukas Nykryn <lnykryn@redhat.com> - 208-12
- units/serial-getty@.service: add [Install] section (#1083936)
- units: order network-online.target after network.target (#1072431)
- util: consider both fuse.glusterfs and glusterfs network file systems (#1080229)
- core: make StopWhenUnneeded work in conjunction with units that fail during their start job (#986949)
- cgroups-agent: down-grade log level (#1044386)
- random-seed: raise POOL_SIZE_MIN constant to 1024 (#1066517)
- delta: do not use unicode chars in C locale (#1088419)
- core: print debug instead of error message (#1105608)
- journald: always add syslog facility for messages coming from kmsg (#1113215)
- fsck,fstab-generator: be lenient about missing fsck.<type> (#1098310)
- rules/60-persistent-storage: add nvme pcie ssd scsi_id ENV (#1042990)
- cgls: fix running with -M option (#1085455)
- getty: Start getty on 3270 terminals available on Linux on System z (#1075729)
- core: Added support for ERRNO NOTIFY_SOCKET  message parsing (#1106457)
- socket: add SocketUser= and SocketGroup= for chown()ing sockets in the file system (#1111761)
- tmpfiles: add --root option to operate on an alternate fs tree (#1111199)
- units: make ExecStopPost action part of ExecStart (#1036276)
- machine-id: only look into KVM uuid when we are not running in a container (#1123452)
- util: reset signals when we fork off agents (#1134818)
- udev: do not skip the execution of RUN when renaming a network device fails (#1102135)
- man: mention System Administrator's Guide in systemctl manpage (#978948)
- vconsole: also copy character maps (not just fonts) from vt1 to vt2, vt3, ... (#1002450)
- localed: consider an unset model as a wildcard (#903776)
- systemd-detect-virt: detect s390 virtualization (#1139149)
- socket: introduce SELinuxContextFromNet option (#1113790)
- sysctl: make --prefix allow all kinds of sysctl paths (#1138591)
- man: mention localectl in locale.conf (#1049286)
- rules: automatically online hot-added CPUs (#968811)
- rules: add rule for naming Dell iDRAC USB Virtual NIC as 'idrac' (#1054477)
- bash-completion: add verb set-property (#1064487)
- man: update journald rate limit defaults (#1145352)
- core: don't try to connect to d-bus after switchroot (#1083300)
- localed: check for partially matching converted keymaps (#1109145)
- fileio: make parse_env_file() return number of parsed items (#1069420)

* Wed Apr 02 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 208-11
- logind-session: save stopping flag (#1082692)
- unit: add waiting jobs to run queue in unit_coldplug (#1083159)

* Fri Mar 28 2014 Harald Hoyer <harald@redhat.com> 208-10
- require redhat-release >= 7.0
Resolves: rhbz#1070114

* Fri Mar 14 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 208-9
- fixes crashes in logind and systemd (#1073994)
- run fsck before mouting root in initramfs (#1056661)

* Thu Mar 06 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 208-8
- rules: mark loop device as SYSTEMD_READY=0 if no file is attached (#1067422)
- utmp: make sure we don't write the utmp reboot record twice on each boot (#1053600)
- rework session shutdown logic (#1047614)
- introduce new stop protocol for unit scopes (#1064976)

* Wed Mar 05 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 208-7
- setup tty permissions and group for /dev/sclp_line0 (#1070310)
- cdrom_id: use the old MMC fallback (#1038015)
- mount: don't send out PropertiesChanged message if actually nothing got changed (#1069718)

* Wed Feb 26 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 208-6
- fix boot if SELINUX=permissive in configuration file and trying to boot in enforcing=1 (#907841)

* Tue Feb 25 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 208-5
- reintroduce 60-alias-kmsg.rules (#1032711)

* Mon Feb 17 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 208-4
- fstab-generator: revert wrongly applied patch

* Fri Feb 14 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 208-3
- dbus-manager: fix selinux check for enable/disable

* Wed Feb 12 2014 Michal Sekletar <msekleta@redhat.com> - 208-2
- require redhat-release package
- call systemd-tmpfiles after package installation (#1059345)
- move preset policy out of systemd package (#903690)

* Tue Feb 11 2014 Michal Sekletar <msekleta@redhat.com> - 208-1
- rebase to systemd-208 (#1063332)
- do not create symlink /etc/systemd/system/syslog.service (#1055421)

* Fri Jan 24 2014 Daniel Mach <dmach@redhat.com> - 207-14
- Mass rebuild 2014-01-24

* Thu Jan 16 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 207-13
- fix SELinux check for transient units (#1008864)

* Wed Jan 15 2014 Lukáš Nykrýn <lnykryn@redhat.com> - 207-12
- shell-completion: remove load and dump from systemctl (#1048066)
- delta: ensure that d_type will be set on every fs (#1050795)
- tmpfiles: don't allow label_fix to print ENOENT when we want to ignore it (#1044871)
- udev/net_id: Introduce predictable network names for Linux on System z (#870859)
- coredumpctl: in case of error free pattern after print (#1052786)

* Fri Dec 27 2013 Daniel Mach <dmach@redhat.com> - 207-11
- Mass rebuild 2013-12-27

* Thu Dec 19 2013 Lukas Nykryn <lnykryn@redhat.com> - 207-10
- cgroup_show: don't call show_pid_array on empty arrays

* Wed Dec 18 2013 Lukas Nykryn <lnykryn@redhat.com> - 207-9
- treat reload failure as failure (#1036848)
- improve journal performance (#1029604)
- backport bugfixes (#1043525)
- fix handling of trailing whitespace in split_quoted (#984832)
- localed: match converted keymaps before legacy (#903776)
- improve the description of parameter X in tmpfiles.d page (#1029604)
- obsolete ConsoleKit (#1039761)
- make rc.local more backward comaptible (#1039465)

* Tue Nov 19 2013 Lukas Nykryn <lnykryn@redhat.com> - 207-8
- tmpfiles: introduce m (#1030961)

* Tue Nov 12 2013 Lukas Nykryn <lnykryn@redhat.com> - 207-7
- introduce DefaultStartLimit (#821723)

* Mon Nov 11 2013 Harald Hoyer <harald@redhat.com> 207-6
- changed systemd-journal-gateway login shell to /sbin/nologin
- backported a lot of bugfixes
- udev: path_id - fix by-path link generation for scm devices
Resolves: rhbz#888707

* Tue Nov 05 2013 Lukas Nykryn <lnykryn@redhat.com> - 207-5
- create /etc/rc.d/rc.local (#968401)
- cgroup: always enable memory.use_hierarchy= for all cgroups (#1011575)
- remove user@.service (#1019738)
- drop some out-of-date references to cgroup settings (#1000004)
- explain NAME in systemctl man page (#978954)

* Tue Oct 15 2013 Lukas Nykryn <lnykryn@redhat.com> - 207-4
- core: whenever a new PID is passed to us, make sure we watch it

* Tue Oct 01 2013 Lukas Nykryn <lnykryn@redhat.com> - 207-3
- presets: add tuned.service

* Thu Sep 19 2013 Lukas Nykryn <lnykryn@redhat.com> - 207-2
- Advertise hibernation only if there's enough free swap
- swap: create .wants symlink to 'auto' swap devices
- Verify validity of session name when received from outside
- polkit: Avoid race condition in scraping /proc
Resolves: rhbz#1005142

* Fri Sep 13 2013 Harald Hoyer <harald@redhat.com> 207-1
- version 207

* Fri Sep 06 2013 Harald Hoyer <harald@redhat.com> 206-8
- support "debug" kernel command line parameter
- journald: fix fd leak in journal_file_empty
- journald: fix vacuuming of archived journals
- libudev: enumerate - do not try to match against an empty subsystem
- cgtop: fixup the online help
- libudev: fix memleak when enumerating childs

* Wed Aug 28 2013 Harald Hoyer <harald@redhat.com> 206-7
- fixed cgroup hashmap corruption
Resolves: rhbz#997742 rhbz#995197

* Fri Aug 23 2013 Harald Hoyer <harald@redhat.com> 206-6
- cgroup.c: check return value of unit_realize_cgroup_now()
Resolves: rhbz#997742 rhbz#995197

* Thu Aug 22 2013 Harald Hoyer <harald@redhat.com> 206-5
- obsolete upstart
Resolves: rhbz#978014
- obsolete hal
Resolves: rhbz#975589
- service: always unwatch PIDs before forgetting old ones
Resolves: rhbz#995197
- units: disable kmod-static-nodes.service in containers
- use CAP_MKNOD ConditionCapability
- fstab-generator: read rd.fstab=on/off switch correctly
- backlight: add minimal tool to save/restore screen brightness
- backlight: instead of syspath use sysname for identifying
- sysctl: allow overwriting of values specified in "later"
- systemd-python: fix initialization of _Reader objects
- udevd: simplify sigterm check
- libudev: fix hwdb validation to look for the *new* file
- units: make fsck units remain after exit
- udev: replace CAP_MKNOD by writable /sys condition
- libudev-enumerate.c:udev_enumerate_get_list_entry() fixed
- journal: fix parsing of facility in syslog messages

* Fri Aug 09 2013 Harald Hoyer <harald@redhat.com> 206-4
- journal: handle multiline syslog messages
- man: Fix copy&paste error
- core: synchronously block when logging
- journal: immediately sync to disk as soon as we receieve an EMERG/ALERT/CRIT message
- initctl: use irreversible jobs when switching runlevels
- udev: log error if chmod/chown of static dev nodes fails
- udev: static_node - don't touch permissions uneccessarily
- tmpfiles: support passing --prefix multiple times
- tmpfiles: introduce --exclude-prefix
- tmpfiles-setup: exclude /dev prefixes files
- logind: update state file after generating the session fifo, not before
- journalctl: use _COMM= match for scripts
- man: systemd.unit: fix volatile path
- man: link up scope+slice units from systemd.unit(5)
- man: there is no session mode, only user mode
- journal: fix hashmap leak in mmap-cache
- systemd-delta: Only print colors when on a tty
- systemd: fix segv in snapshot creation
- udev: hwdb - try reading modalias for usb before falling back to the composed one
- udevd: respect the log-level set in /etc/udev/udev.conf
- fstab-generator: respect noauto/nofail when adding sysroot mount

* Fri Aug 02 2013 Lukáš Nykrýn <lnykryn@redhat.com> - 206-3
- add dependency on kmod >= 14
- remove /var/log/journal to make journal non-persistant (#989750)
- add hypervkvpd.service to presets (#924321)

* Thu Aug 01 2013 Lukáš Nykrýn <lnykryn@redhat.com> - 206-2
- 80-net-name-slot.rules: only rename network interfaces on ACTION==add

* Tue Jul 23 2013 Kay Sievers <kay@redhat.com> - 206-1
- New upstream release
Resolves (#984152)

* Wed Jul  3 2013 Lennart Poettering <lpoetter@redhat.com> - 205-1
- New upstream release

* Wed Jun 26 2013 Michal Schmidt <mschmidt@redhat.com> 204-10
- Split systemd-journal-gateway subpackage (#908081).

* Mon Jun 24 2013 Michal Schmidt <mschmidt@redhat.com> 204-9
- Rename nm_dispatcher to NetworkManager-dispatcher in default preset (#977433)

* Fri Jun 14 2013 Harald Hoyer <harald@redhat.com> 204-8
- fix, which helps to sucessfully browse journals with
duplicated seqnums

* Fri Jun 14 2013 Harald Hoyer <harald@redhat.com> 204-7
- fix duplicate message ID bug
Resolves: rhbz#974132

* Thu Jun 06 2013 Harald Hoyer <harald@redhat.com> 204-6
- introduce 99-default-disable.preset

* Thu Jun  6 2013 Lennart Poettering <lpoetter@redhat.com> - 204-5
- Rename 90-display-manager.preset to 85-display-manager.preset so that it actually takes precedence over 90-default.preset's "disable *" line (#903690)

* Tue May 28 2013 Harald Hoyer <harald@redhat.com> 204-4
- Fix kernel-install (#965897)

* Wed May 22 2013 Kay Sievers <kay@redhat.com> - 204-3
- Fix kernel-install (#965897)

* Thu May  9 2013 Lennart Poettering <lpoetter@redhat.com> - 204-2
- New upstream release
- disable isdn by default (#959793)

* Tue May 07 2013 Harald Hoyer <harald@redhat.com> 203-2
- forward port kernel-install-grubby.patch

* Tue May  7 2013 Lennart Poettering <lpoetter@redhat.com> - 203-1
- New upstream release

* Wed Apr 24 2013 Harald Hoyer <harald@redhat.com> 202-3
- fix ENOENT for getaddrinfo
- Resolves: rhbz#954012 rhbz#956035
- crypt-setup-generator: correctly check return of strdup
- logind-dbus: initialize result variable
- prevent library underlinking

* Fri Apr 19 2013 Harald Hoyer <harald@redhat.com> 202-2
- nspawn create empty /etc/resolv.conf if necessary
- python wrapper: add sd_journal_add_conjunction()
- fix s390 booting
- Resolves: rhbz#953217

* Thu Apr 18 2013 Lennart Poettering <lpoetter@redhat.com> - 202-1
- New upstream release

* Tue Apr 09 2013 Michal Schmidt <mschmidt@redhat.com> - 201-2
- Automatically discover whether to run autoreconf and add autotools and git
BuildRequires based on the presence of patches to be applied.
- Use find -delete.

* Mon Apr  8 2013 Lennart Poettering <lpoetter@redhat.com> - 201-1
- New upstream release

* Mon Apr  8 2013 Lennart Poettering <lpoetter@redhat.com> - 200-4
- Update preset file

* Fri Mar 29 2013 Lennart Poettering <lpoetter@redhat.com> - 200-3
- Remove NetworkManager-wait-online.service from presets file again, it should default to off

* Fri Mar 29 2013 Lennart Poettering <lpoetter@redhat.com> - 200-2
- New upstream release

* Tue Mar 26 2013 Lennart Poettering <lpoetter@redhat.com> - 199-2
- Add NetworkManager-wait-online.service to the presets file

* Tue Mar 26 2013 Lennart Poettering <lpoetter@redhat.com> - 199-1
- New upstream release

* Mon Mar 18 2013 Michal Schmidt <mschmidt@redhat.com> 198-7
- Drop /usr/s?bin/ prefixes.

* Fri Mar 15 2013 Harald Hoyer <harald@redhat.com> 198-6
- run autogen to pickup all changes

* Fri Mar 15 2013 Harald Hoyer <harald@redhat.com> 198-5
- do not mount anything, when not running as pid 1
- add initrd.target for systemd in the initrd

* Wed Mar 13 2013 Harald Hoyer <harald@redhat.com> 198-4
- fix switch-root and local-fs.target problem
- patch kernel-install to use grubby, if available

* Fri Mar 08 2013 Harald Hoyer <harald@redhat.com> 198-3
- add Conflict with dracut < 026 because of the new switch-root isolate

* Thu Mar  7 2013 Lennart Poettering <lpoetter@redhat.com> - 198-2
- Create required users

* Thu Mar 7 2013 Lennart Poettering <lpoetter@redhat.com> - 198-1
- New release
- Enable journal persistancy by default

* Sun Feb 10 2013 Peter Robinson <pbrobinson@fedoraproject.org> 197-3
- Bump for ARM

* Fri Jan 18 2013 Michal Schmidt <mschmidt@redhat.com> - 197-2
- Added qemu-guest-agent.service to presets (Lennart, #885406).
- Add missing pygobject3-base to systemd-analyze deps (Lennart).
- Do not require hwdata, it is all in the hwdb now (Kay).
- Drop dependency on dbus-python.

* Tue Jan  8 2013 Lennart Poettering <lpoetter@redhat.com> - 197-1
- New upstream release

* Mon Dec 10 2012 Michal Schmidt <mschmidt@redhat.com> - 196-4
- Enable rngd.service by default (#857765).

* Mon Dec 10 2012 Michal Schmidt <mschmidt@redhat.com> - 196-3
- Disable hardening on s390(x) because PIE is broken there and produces
text relocations with __thread (#868839).

* Wed Dec 05 2012 Michal Schmidt <mschmidt@redhat.com> - 196-2
- added spice-vdagentd.service to presets (Lennart, #876237)
- BR cryptsetup-devel instead of the legacy cryptsetup-luks-devel provide name
(requested by Milan Brož).
- verbose make to see the actual build flags

* Wed Nov 21 2012 Lennart Poettering <lpoetter@redhat.com> - 196-1
- New upstream release

* Tue Nov 20 2012 Lennart Poettering <lpoetter@redhat.com> - 195-8
- https://bugzilla.redhat.com/show_bug.cgi?id=873459
- https://bugzilla.redhat.com/show_bug.cgi?id=878093

* Thu Nov 15 2012 Michal Schmidt <mschmidt@redhat.com> - 195-7
- Revert udev killing cgroup patch for F18 Beta.
- https://bugzilla.redhat.com/show_bug.cgi?id=873576

* Fri Nov 09 2012 Michal Schmidt <mschmidt@redhat.com> - 195-6
- Fix cyclical dep between systemd and systemd-libs.
- Avoid broken build of test-journal-syslog.
- https://bugzilla.redhat.com/show_bug.cgi?id=873387
- https://bugzilla.redhat.com/show_bug.cgi?id=872638

* Thu Oct 25 2012 Kay Sievers <kay@redhat.com> - 195-5
- require 'sed', limit HOSTNAME= match

* Wed Oct 24 2012 Michal Schmidt <mschmidt@redhat.com> - 195-4
- add dmraid-activation.service to the default preset
- add yum protected.d fragment
- https://bugzilla.redhat.com/show_bug.cgi?id=869619
- https://bugzilla.redhat.com/show_bug.cgi?id=869717

* Wed Oct 24 2012 Kay Sievers <kay@redhat.com> - 195-3
- Migrate /etc/sysconfig/ i18n, keyboard, network files/variables to
systemd native files

* Tue Oct 23 2012 Lennart Poettering <lpoetter@redhat.com> - 195-2
- Provide syslog because the journal is fine as a syslog implementation

* Tue Oct 23 2012 Lennart Poettering <lpoetter@redhat.com> - 195-1
- New upstream release
- https://bugzilla.redhat.com/show_bug.cgi?id=831665
- https://bugzilla.redhat.com/show_bug.cgi?id=847720
- https://bugzilla.redhat.com/show_bug.cgi?id=858693
- https://bugzilla.redhat.com/show_bug.cgi?id=863481
- https://bugzilla.redhat.com/show_bug.cgi?id=864629
- https://bugzilla.redhat.com/show_bug.cgi?id=864672
- https://bugzilla.redhat.com/show_bug.cgi?id=864674
- https://bugzilla.redhat.com/show_bug.cgi?id=865128
- https://bugzilla.redhat.com/show_bug.cgi?id=866346
- https://bugzilla.redhat.com/show_bug.cgi?id=867407
- https://bugzilla.redhat.com/show_bug.cgi?id=868603

* Wed Oct 10 2012 Michal Schmidt <mschmidt@redhat.com> - 194-2
- Add scriptlets for migration away from systemd-timedated-ntp.target

* Wed Oct  3 2012 Lennart Poettering <lpoetter@redhat.com> - 194-1
- New upstream release
- https://bugzilla.redhat.com/show_bug.cgi?id=859614
- https://bugzilla.redhat.com/show_bug.cgi?id=859655

* Fri Sep 28 2012 Lennart Poettering <lpoetter@redhat.com> - 193-1
- New upstream release

* Tue Sep 25 2012 Lennart Poettering <lpoetter@redhat.com> - 192-1
- New upstream release

* Fri Sep 21 2012 Lennart Poettering <lpoetter@redhat.com> - 191-2
- Fix journal mmap header prototype definition to fix compilation on 32bit

* Fri Sep 21 2012 Lennart Poettering <lpoetter@redhat.com> - 191-1
- New upstream release
- Enable all display managers by default, as discussed with Adam Williamson

* Thu Sep 20 2012 Lennart Poettering <lpoetter@redhat.com> - 190-1
- New upstream release
- Take possession of /etc/localtime, and remove /etc/sysconfig/clock
- https://bugzilla.redhat.com/show_bug.cgi?id=858780
- https://bugzilla.redhat.com/show_bug.cgi?id=858787
- https://bugzilla.redhat.com/show_bug.cgi?id=858771
- https://bugzilla.redhat.com/show_bug.cgi?id=858754
- https://bugzilla.redhat.com/show_bug.cgi?id=858746
- https://bugzilla.redhat.com/show_bug.cgi?id=858266
- https://bugzilla.redhat.com/show_bug.cgi?id=858224
- https://bugzilla.redhat.com/show_bug.cgi?id=857670
- https://bugzilla.redhat.com/show_bug.cgi?id=856975
- https://bugzilla.redhat.com/show_bug.cgi?id=855863
- https://bugzilla.redhat.com/show_bug.cgi?id=851970
- https://bugzilla.redhat.com/show_bug.cgi?id=851275
- https://bugzilla.redhat.com/show_bug.cgi?id=851131
- https://bugzilla.redhat.com/show_bug.cgi?id=847472
- https://bugzilla.redhat.com/show_bug.cgi?id=847207
- https://bugzilla.redhat.com/show_bug.cgi?id=846483
- https://bugzilla.redhat.com/show_bug.cgi?id=846085
- https://bugzilla.redhat.com/show_bug.cgi?id=845973
- https://bugzilla.redhat.com/show_bug.cgi?id=845194
- https://bugzilla.redhat.com/show_bug.cgi?id=845028
- https://bugzilla.redhat.com/show_bug.cgi?id=844630
- https://bugzilla.redhat.com/show_bug.cgi?id=839736
- https://bugzilla.redhat.com/show_bug.cgi?id=835848
- https://bugzilla.redhat.com/show_bug.cgi?id=831740
- https://bugzilla.redhat.com/show_bug.cgi?id=823485
- https://bugzilla.redhat.com/show_bug.cgi?id=821813
- https://bugzilla.redhat.com/show_bug.cgi?id=807886
- https://bugzilla.redhat.com/show_bug.cgi?id=802198
- https://bugzilla.redhat.com/show_bug.cgi?id=767795
- https://bugzilla.redhat.com/show_bug.cgi?id=767561
- https://bugzilla.redhat.com/show_bug.cgi?id=752774
- https://bugzilla.redhat.com/show_bug.cgi?id=732874
- https://bugzilla.redhat.com/show_bug.cgi?id=858735

* Thu Sep 13 2012 Lennart Poettering <lpoetter@redhat.com> - 189-4
- Don't pull in pkg-config as dep
- https://bugzilla.redhat.com/show_bug.cgi?id=852828

* Wed Sep 12 2012 Lennart Poettering <lpoetter@redhat.com> - 189-3
- Update preset policy
- Rename preset policy file from 99-default.preset to 90-default.preset so that people can order their own stuff after the Fedora default policy if they wish

* Thu Aug 23 2012 Lennart Poettering <lpoetter@redhat.com> - 189-2
- Update preset policy
- https://bugzilla.redhat.com/show_bug.cgi?id=850814

* Thu Aug 23 2012 Lennart Poettering <lpoetter@redhat.com> - 189-1
- New upstream release

* Thu Aug 16 2012 Ray Strode <rstrode@redhat.com> 188-4
- more scriptlet fixes
(move dm migration logic to %%posttrans so the service
files it's looking for are available at the time
the logic is run)

* Sat Aug 11 2012 Lennart Poettering <lpoetter@redhat.com> - 188-3
- Remount file systems MS_PRIVATE before switching roots
- https://bugzilla.redhat.com/show_bug.cgi?id=847418

* Wed Aug 08 2012 Rex Dieter <rdieter@fedoraproject.org> - 188-2
- fix scriptlets

* Wed Aug  8 2012 Lennart Poettering <lpoetter@redhat.com> - 188-1
- New upstream release
- Enable gdm and avahi by default via the preset file
- Convert /etc/sysconfig/desktop to display-manager.service symlink
- Enable hardened build

* Mon Jul 30 2012 Kay Sievers <kay@redhat.com> - 187-3
- Obsolete: system-setup-keyboard

* Wed Jul 25 2012 Kalev Lember <kalevlember@gmail.com> - 187-2
- Run ldconfig for the new -libs subpackage

* Thu Jul 19 2012 Lennart Poettering <lpoetter@redhat.com> - 187-1
- New upstream release

* Mon Jul 09 2012 Harald Hoyer <harald@redhat.com> 186-2
- fixed dracut conflict version

* Tue Jul  3 2012 Lennart Poettering <lpoetter@redhat.com> - 186-1
- New upstream release

* Fri Jun 22 2012 Nils Philippsen <nils@redhat.com> - 185-7.gite7aee75
- add obsoletes/conflicts so multilib systemd -> systemd-libs updates work

* Thu Jun 14 2012 Michal Schmidt <mschmidt@redhat.com> - 185-6.gite7aee75
- Update to current git

* Wed Jun 06 2012 Kay Sievers - 185-5.gita2368a3
- disable plymouth in configure, to drop the .wants/ symlinks

* Wed Jun 06 2012 Michal Schmidt <mschmidt@redhat.com> - 185-4.gita2368a3
- Update to current git snapshot
- Add systemd-readahead-analyze
- Drop upstream patch
- Split systemd-libs
- Drop duplicate doc files
- Fixed License headers of subpackages

* Wed Jun 06 2012 Ray Strode <rstrode@redhat.com> - 185-3
- Drop plymouth files
- Conflict with old plymouth

* Tue Jun 05 2012 Kay Sievers - 185-2
- selinux udev labeling fix
- conflict with older dracut versions for new udev file names

* Mon Jun 04 2012 Kay Sievers - 185-1
- New upstream release
- udev selinux labeling fixes
- new man pages
- systemctl help <unit name>

* Thu May 31 2012 Lennart Poettering <lpoetter@redhat.com> - 184-1
- New upstream release

* Thu May 24 2012 Kay Sievers <kay@redhat.com> - 183-1
- New upstream release including udev merge.

* Wed Mar 28 2012 Michal Schmidt <mschmidt@redhat.com> - 44-4
- Add triggers from Bill Nottingham to correct the damage done by
the obsoleted systemd-units's preun scriptlet (#807457).

* Mon Mar 26 2012 Dennis Gilmore <dennis@ausil.us> - 44-3
- apply patch from upstream so we can build systemd on arm and ppc
- and likely the rest of the secondary arches

* Tue Mar 20 2012 Michal Schmidt <mschmidt@redhat.com> - 44-2
- Don't build the gtk parts anymore. They're moving into systemd-ui.
- Remove a dead patch file.

* Fri Mar 16 2012 Lennart Poettering <lpoetter@redhat.com> - 44-1
- New upstream release
- Closes #798760, #784921, #783134, #768523, #781735

* Mon Feb 27 2012 Dennis Gilmore <dennis@ausil.us> - 43-2
- don't conflict with fedora-release systemd never actually provided
- /etc/os-release so there is no actual conflict

* Wed Feb 15 2012 Lennart Poettering <lpoetter@redhat.com> - 43-1
- New upstream release
- Closes #789758, #790260, #790522

* Sat Feb 11 2012 Lennart Poettering <lpoetter@redhat.com> - 42-1
- New upstream release
- Save a bit of entropy during system installation (#789407)
- Don't own /etc/os-release anymore, leave that to fedora-release

* Thu Feb  9 2012 Adam Williamson <awilliam@redhat.com> - 41-2
- rebuild for fixed binutils

* Thu Feb  9 2012 Lennart Poettering <lpoetter@redhat.com> - 41-1
- New upstream release

* Tue Feb  7 2012 Lennart Poettering <lpoetter@redhat.com> - 40-1
- New upstream release

* Thu Jan 26 2012 Kay Sievers <kay@redhat.com> - 39-3
- provide /sbin/shutdown

* Wed Jan 25 2012 Harald Hoyer <harald@redhat.com> 39-2
- increment release

* Wed Jan 25 2012 Kay Sievers <kay@redhat.com> - 39-1.1
- install everything in /usr
https://fedoraproject.org/wiki/Features/UsrMove

* Wed Jan 25 2012 Lennart Poettering <lpoetter@redhat.com> - 39-1
- New upstream release

* Sun Jan 22 2012 Michal Schmidt <mschmidt@redhat.com> - 38-6.git9fa2f41
- Update to a current git snapshot.
- Resolves: #781657

* Sun Jan 22 2012 Michal Schmidt <mschmidt@redhat.com> - 38-5
- Build against libgee06. Reenable gtk tools.
- Delete unused patches.
- Add easy building of git snapshots.
- Remove legacy spec file elements.
- Don't mention implicit BuildRequires.
- Configure with --disable-static.
- Merge -units into the main package.
- Move section 3 manpages to -devel.
- Fix unowned directory.
- Run ldconfig in scriptlets.
- Split systemd-analyze to a subpackage.

* Sat Jan 21 2012 Dan Horák <dan[at]danny.cz> - 38-4
- fix build on big-endians

* Wed Jan 11 2012 Lennart Poettering <lpoetter@redhat.com> - 38-3
- Disable building of gtk tools for now

* Wed Jan 11 2012 Lennart Poettering <lpoetter@redhat.com> - 38-2
- Fix a few (build) dependencies

* Wed Jan 11 2012 Lennart Poettering <lpoetter@redhat.com> - 38-1
- New upstream release

* Tue Nov 15 2011 Michal Schmidt <mschmidt@redhat.com> - 37-4
- Run authconfig if /etc/pam.d/system-auth is not a symlink.
- Resolves: #753160

* Wed Nov 02 2011 Michal Schmidt <mschmidt@redhat.com> - 37-3
- Fix remote-fs-pre.target and its ordering.
- Resolves: #749940

* Wed Oct 19 2011 Michal Schmidt <mschmidt@redhat.com> - 37-2
- A couple of fixes from upstream:
- Fix a regression in bash-completion reported in Bodhi.
- Fix a crash in isolating.
- Resolves: #717325

* Tue Oct 11 2011 Lennart Poettering <lpoetter@redhat.com> - 37-1
- New upstream release
- Resolves: #744726, #718464, #713567, #713707, #736756

* Thu Sep 29 2011 Michal Schmidt <mschmidt@redhat.com> - 36-5
- Undo the workaround. Kay says it does not belong in systemd.
- Unresolves: #741655

* Thu Sep 29 2011 Michal Schmidt <mschmidt@redhat.com> - 36-4
- Workaround for the crypto-on-lvm-on-crypto disk layout
- Resolves: #741655

* Sun Sep 25 2011 Michal Schmidt <mschmidt@redhat.com> - 36-3
- Revert an upstream patch that caused ordering cycles
- Resolves: #741078

* Fri Sep 23 2011 Lennart Poettering <lpoetter@redhat.com> - 36-2
- Add /etc/timezone to ghosted files

* Fri Sep 23 2011 Lennart Poettering <lpoetter@redhat.com> - 36-1
- New upstream release
- Resolves: #735013, #736360, #737047, #737509, #710487, #713384

* Thu Sep  1 2011 Lennart Poettering <lpoetter@redhat.com> - 35-1
- New upstream release
- Update post scripts
- Resolves: #726683, #713384, #698198, #722803, #727315, #729997, #733706, #734611

* Thu Aug 25 2011 Lennart Poettering <lpoetter@redhat.com> - 34-1
- New upstream release

* Fri Aug 19 2011 Harald Hoyer <harald@redhat.com> 33-2
- fix ABRT on service file reloading
- Resolves: rhbz#732020

* Wed Aug  3 2011 Lennart Poettering <lpoetter@redhat.com> - 33-1
- New upstream release

* Fri Jul 29 2011 Lennart Poettering <lpoetter@redhat.com> - 32-1
- New upstream release

* Wed Jul 27 2011 Lennart Poettering <lpoetter@redhat.com> - 31-2
- Fix access mode of modprobe file, restart logind after upgrade

* Wed Jul 27 2011 Lennart Poettering <lpoetter@redhat.com> - 31-1
- New upstream release

* Wed Jul 13 2011 Lennart Poettering <lpoetter@redhat.com> - 30-1
- New upstream release

* Thu Jun 16 2011 Lennart Poettering <lpoetter@redhat.com> - 29-1
- New upstream release

* Mon Jun 13 2011 Michal Schmidt <mschmidt@redhat.com> - 28-4
- Apply patches from current upstream.
- Fixes memory size detection on 32-bit with >4GB RAM (BZ712341)

* Wed Jun 08 2011 Michal Schmidt <mschmidt@redhat.com> - 28-3
- Apply patches from current upstream
- https://bugzilla.redhat.com/show_bug.cgi?id=709909
- https://bugzilla.redhat.com/show_bug.cgi?id=710839
- https://bugzilla.redhat.com/show_bug.cgi?id=711015

* Sat May 28 2011 Lennart Poettering <lpoetter@redhat.com> - 28-2
- Pull in nss-myhostname

* Thu May 26 2011 Lennart Poettering <lpoetter@redhat.com> - 28-1
- New upstream release

* Wed May 25 2011 Lennart Poettering <lpoetter@redhat.com> - 26-2
- Bugfix release
- https://bugzilla.redhat.com/show_bug.cgi?id=707507
- https://bugzilla.redhat.com/show_bug.cgi?id=707483
- https://bugzilla.redhat.com/show_bug.cgi?id=705427
- https://bugzilla.redhat.com/show_bug.cgi?id=707577

* Sat Apr 30 2011 Lennart Poettering <lpoetter@redhat.com> - 26-1
- New upstream release
- https://bugzilla.redhat.com/show_bug.cgi?id=699394
- https://bugzilla.redhat.com/show_bug.cgi?id=698198
- https://bugzilla.redhat.com/show_bug.cgi?id=698674
- https://bugzilla.redhat.com/show_bug.cgi?id=699114
- https://bugzilla.redhat.com/show_bug.cgi?id=699128

* Thu Apr 21 2011 Lennart Poettering <lpoetter@redhat.com> - 25-1
- New upstream release
- https://bugzilla.redhat.com/show_bug.cgi?id=694788
- https://bugzilla.redhat.com/show_bug.cgi?id=694321
- https://bugzilla.redhat.com/show_bug.cgi?id=690253
- https://bugzilla.redhat.com/show_bug.cgi?id=688661
- https://bugzilla.redhat.com/show_bug.cgi?id=682662
- https://bugzilla.redhat.com/show_bug.cgi?id=678555
- https://bugzilla.redhat.com/show_bug.cgi?id=628004

* Wed Apr  6 2011 Lennart Poettering <lpoetter@redhat.com> - 24-1
- New upstream release
- https://bugzilla.redhat.com/show_bug.cgi?id=694079
- https://bugzilla.redhat.com/show_bug.cgi?id=693289
- https://bugzilla.redhat.com/show_bug.cgi?id=693274
- https://bugzilla.redhat.com/show_bug.cgi?id=693161

* Tue Apr  5 2011 Lennart Poettering <lpoetter@redhat.com> - 23-1
- New upstream release
- Include systemd-sysv-convert

* Fri Apr  1 2011 Lennart Poettering <lpoetter@redhat.com> - 22-1
- New upstream release

* Wed Mar 30 2011 Lennart Poettering <lpoetter@redhat.com> - 21-2
- The quota services are now pulled in by mount points, hence no need to enable them explicitly

* Tue Mar 29 2011 Lennart Poettering <lpoetter@redhat.com> - 21-1
- New upstream release

* Mon Mar 28 2011 Matthias Clasen <mclasen@redhat.com> - 20-2
- Apply upstream patch to not send untranslated messages to plymouth

* Tue Mar  8 2011 Lennart Poettering <lpoetter@redhat.com> - 20-1
- New upstream release

* Tue Mar  1 2011 Lennart Poettering <lpoetter@redhat.com> - 19-1
- New upstream release

* Wed Feb 16 2011 Lennart Poettering <lpoetter@redhat.com> - 18-1
- New upstream release

* Mon Feb 14 2011 Bill Nottingham <notting@redhat.com> - 17-6
- bump upstart obsoletes (#676815)

* Wed Feb  9 2011 Tom Callaway <spot@fedoraproject.org> - 17-5
- add macros.systemd file for %%{_unitdir}

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 17-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Wed Feb  9 2011 Lennart Poettering <lpoetter@redhat.com> - 17-3
- Fix popen() of systemctl, #674916

* Mon Feb  7 2011 Bill Nottingham <notting@redhat.com> - 17-2
- add epoch to readahead obsolete

* Sat Jan 22 2011 Lennart Poettering <lpoetter@redhat.com> - 17-1
- New upstream release

* Tue Jan 18 2011 Lennart Poettering <lpoetter@redhat.com> - 16-2
- Drop console.conf again, since it is not shipped in pamtmp.conf

* Sat Jan  8 2011 Lennart Poettering <lpoetter@redhat.com> - 16-1
- New upstream release

* Thu Nov 25 2010 Lennart Poettering <lpoetter@redhat.com> - 15-1
- New upstream release

* Thu Nov 25 2010 Lennart Poettering <lpoetter@redhat.com> - 14-1
- Upstream update
- Enable hwclock-load by default
- Obsolete readahead
- Enable /var/run and /var/lock on tmpfs

* Fri Nov 19 2010 Lennart Poettering <lpoetter@redhat.com> - 13-1
- new upstream release

* Wed Nov 17 2010 Bill Nottingham <notting@redhat.com> 12-3
- Fix clash

* Wed Nov 17 2010 Lennart Poettering <lpoetter@redhat.com> - 12-2
- Don't clash with initscripts for now, so that we don't break the builders

* Wed Nov 17 2010 Lennart Poettering <lpoetter@redhat.com> - 12-1
- New upstream release

* Fri Nov 12 2010 Matthias Clasen <mclasen@redhat.com> - 11-2
- Rebuild with newer vala, libnotify

* Thu Oct  7 2010 Lennart Poettering <lpoetter@redhat.com> - 11-1
- New upstream release

* Wed Sep 29 2010 Jesse Keating <jkeating@redhat.com> - 10-6
- Rebuilt for gcc bug 634757

* Thu Sep 23 2010 Bill Nottingham <notting@redhat.com> - 10-5
- merge -sysvinit into main package

* Mon Sep 20 2010 Bill Nottingham <notting@redhat.com> - 10-4
- obsolete upstart-sysvinit too

* Fri Sep 17 2010 Bill Nottingham <notting@redhat.com> - 10-3
- Drop upstart requires

* Tue Sep 14 2010 Lennart Poettering <lpoetter@redhat.com> - 10-2
- Enable audit
- https://bugzilla.redhat.com/show_bug.cgi?id=633771

* Tue Sep 14 2010 Lennart Poettering <lpoetter@redhat.com> - 10-1
- New upstream release
- https://bugzilla.redhat.com/show_bug.cgi?id=630401
- https://bugzilla.redhat.com/show_bug.cgi?id=630225
- https://bugzilla.redhat.com/show_bug.cgi?id=626966
- https://bugzilla.redhat.com/show_bug.cgi?id=623456

* Fri Sep  3 2010 Bill Nottingham <notting@redhat.com> - 9-3
- move fedora-specific units to initscripts; require newer version thereof

* Fri Sep  3 2010 Lennart Poettering <lpoetter@redhat.com> - 9-2
- Add missing tarball

* Fri Sep  3 2010 Lennart Poettering <lpoetter@redhat.com> - 9-1
- New upstream version
- Closes 501720, 614619, 621290, 626443, 626477, 627014, 627785, 628913

* Fri Aug 27 2010 Lennart Poettering <lpoetter@redhat.com> - 8-3
- Reexecute after installation, take ownership of /var/run/user
- https://bugzilla.redhat.com/show_bug.cgi?id=627457
- https://bugzilla.redhat.com/show_bug.cgi?id=627634

* Thu Aug 26 2010 Lennart Poettering <lpoetter@redhat.com> - 8-2
- Properly create default.target link

* Wed Aug 25 2010 Lennart Poettering <lpoetter@redhat.com> - 8-1
- New upstream release

* Thu Aug 12 2010 Lennart Poettering <lpoetter@redhat.com> - 7-3
- Fix https://bugzilla.redhat.com/show_bug.cgi?id=623561

* Thu Aug 12 2010 Lennart Poettering <lpoetter@redhat.com> - 7-2
- Fix https://bugzilla.redhat.com/show_bug.cgi?id=623430

* Tue Aug 10 2010 Lennart Poettering <lpoetter@redhat.com> - 7-1
- New upstream release

* Fri Aug  6 2010 Lennart Poettering <lpoetter@redhat.com> - 6-2
- properly hide output on package installation
- pull in coreutils during package installtion

* Fri Aug  6 2010 Lennart Poettering <lpoetter@redhat.com> - 6-1
- New upstream release
- Fixes #621200

* Wed Aug  4 2010 Lennart Poettering <lpoetter@redhat.com> - 5-2
- Add tarball

* Wed Aug  4 2010 Lennart Poettering <lpoetter@redhat.com> - 5-1
- Prepare release 5

* Tue Jul 27 2010 Bill Nottingham <notting@redhat.com> - 4-4
- Add 'sysvinit-userspace' provide to -sysvinit package to fix upgrade/install (#618537)

* Sat Jul 24 2010 Lennart Poettering <lpoetter@redhat.com> - 4-3
- Add libselinux to build dependencies

* Sat Jul 24 2010 Lennart Poettering <lpoetter@redhat.com> - 4-2
- Use the right tarball

* Sat Jul 24 2010 Lennart Poettering <lpoetter@redhat.com> - 4-1
- New upstream release, and make default

* Tue Jul 13 2010 Lennart Poettering <lpoetter@redhat.com> - 3-3
- Used wrong tarball

* Tue Jul 13 2010 Lennart Poettering <lpoetter@redhat.com> - 3-2
- Own /cgroup jointly with libcgroup, since we don't dpend on it anymore

* Tue Jul 13 2010 Lennart Poettering <lpoetter@redhat.com> - 3-1
- New upstream release

* Fri Jul 9 2010 Lennart Poettering <lpoetter@redhat.com> - 2-0
- New upstream release

* Wed Jul 7 2010 Lennart Poettering <lpoetter@redhat.com> - 1-0
- First upstream release

* Tue Jun 29 2010 Lennart Poettering <lpoetter@redhat.com> - 0-0.7.20100629git4176e5
- New snapshot
- Split off -units package where other packages can depend on without pulling in the whole of systemd

* Tue Jun 22 2010 Lennart Poettering <lpoetter@redhat.com> - 0-0.6.20100622gita3723b
- Add missing libtool dependency.

* Tue Jun 22 2010 Lennart Poettering <lpoetter@redhat.com> - 0-0.5.20100622gita3723b
- Update snapshot

* Mon Jun 14 2010 Rahul Sundaram <sundaram@fedoraproject.org> - 0-0.4.20100614git393024
- Pull the latest snapshot that fixes a segfault. Resolves rhbz#603231

* Fri Jun 11 2010 Rahul Sundaram <sundaram@fedoraproject.org> - 0-0.3.20100610git2f198e
- More minor fixes as per review

* Thu Jun 10 2010 Rahul Sundaram <sundaram@fedoraproject.org> - 0-0.2.20100610git2f198e
- Spec improvements from David Hollis

* Wed Jun 09 2010 Rahul Sundaram <sundaram@fedoraproject.org> - 0-0.1.20090609git2f198e
- Address review comments

* Tue Jun 01 2010 Rahul Sundaram <sundaram@fedoraproject.org> - 0-0.0.git2010-06-02
- Initial spec (adopted from Kay Sievers)

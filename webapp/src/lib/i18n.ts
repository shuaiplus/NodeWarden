type Locale = 'en' | 'zh-CN';

const LOCALE_STORAGE_KEY = 'nodewarden.locale';

const messages: Record<Locale, Record<string, string>> = {
  en: {
    nav_account_settings: "Account Settings",
    nav_admin_panel: "Admin Panel",
    nav_device_management: "Device Management",
    nav_my_vault: "My Vault",
    nav_sends: "Sends",
    nav_backup_strategy: "Backup Strategy",
    nav_import_export: "Import & Export",
    backup_strategy_title: "Backup Strategy",
    backup_strategy_under_construction: "Under construction.",
    import_export_title: "Import & Export",
    import_export_under_construction: "Under construction.",
    txt_access_count: "Access Count",
    txt_accessed_count_times: "Accessed {count} times",
    txt_actions: "Actions",
    txt_add: "Add",
    txt_add_field: "Add Field",
    txt_add_website: "Add Website",
    txt_added: "Added",
    txt_additional_options: "Additional Options",
    txt_address: "Address",
    txt_address_1: "Address 1",
    txt_address_2: "Address 2",
    txt_address_3: "Address 3",
    txt_all_device_authorizations_revoked: "All device authorizations revoked",
    txt_all_invites_deleted: "All invites deleted",
    txt_all_items: "All Items",
    txt_all_sends: "All Sends",
    txt_android: "Android",
    txt_are_you_sure_you_want_to_delete_count_selected_items: "Are you sure you want to delete {count} selected items?",
    txt_are_you_sure_you_want_to_delete_this_item: "Are you sure you want to delete this item?",
    txt_are_you_sure_you_want_to_log_out: "Are you sure you want to log out?",
    txt_authenticator_key: "Authenticator Key",
    txt_authorized_devices: "Authorized Devices",
    txt_auto_copy_link_after_save: "Auto copy link after save",
    txt_autofill_options: "Autofill Options",
    txt_back_to_login: "Back To Login",
    txt_ban: "Ban",
    txt_boolean: "Boolean",
    txt_brand: "Brand",
    txt_bulk_delete_failed: "Bulk delete failed",
    txt_bulk_delete_sends_failed: "Bulk delete sends failed",
    txt_bulk_move_failed: "Bulk move failed",
    txt_cancel: "Cancel",
    txt_card: "Card",
    txt_card_details: "Card Details",
    txt_cardholder_name: "Cardholder Name",
    txt_change_master_password: "Change Master Password",
    txt_change_password: "Change Password",
    txt_change_password_failed: "Change password failed",
    txt_checked: "Checked",
    txt_choose_destination_folder: "Choose destination folder.",
    txt_chrome_browser: "Chrome Browser",
    txt_chrome_extension: "Chrome Extension",
    txt_city_town: "City / Town",
    txt_code: "Code",
    txt_company: "Company",
    txt_configure_custom_field_values: "Configure custom field values.",
    txt_confirm: "Confirm",
    txt_confirm_master_password: "Confirm Master Password",
    txt_confirm_password: "Confirm Password",
    txt_copy: "Copy",
    txt_copy_code: "Copy Code",
    txt_copy_link: "Copy Link",
    txt_copy_secret: "Copy Secret",
    txt_country: "Country",
    txt_create: "Create",
    txt_create_account: "Create Account",
    txt_create_folder: "Create Folder",
    txt_create_folder_failed: "Create folder failed",
    txt_create_item_failed: "Create item failed",
    txt_create_send_failed: "Create send failed",
    txt_create_timed_invite: "Create Timed Invite",
    txt_created_value: "Created: {value}",
    txt_current_new_password_is_required: "Current/new password is required",
    txt_current_password: "Current Password",
    txt_custom_fields: "Custom Fields",
    txt_decrypt_failed: "(Decrypt failed)",
    txt_decrypt_failed_2: "Decrypt failed",
    txt_delete: "Delete",
    txt_delete_all: "Delete All",
    txt_delete_all_invite_codes_active_inactive: "Delete all invite codes (active/inactive)?",
    txt_delete_all_invites: "Delete all invites",
    txt_delete_item: "Delete Item",
    txt_delete_item_failed: "Delete item failed",
    txt_delete_selected: "Delete Selected",
    txt_delete_selected_items: "Delete Selected Items",
    txt_delete_send_failed: "Delete send failed",
    txt_delete_this_user_and_all_user_data: "Delete this user and all user data?",
    txt_delete_user: "Delete user",
    txt_deleted_selected_items: "Deleted selected items",
    txt_deleted_selected_sends: "Deleted selected sends",
    txt_deletion_date: "Deletion Date",
    txt_deletion_days: "Deletion Days",
    txt_device: "Device",
    txt_device_authorization_revoked: "Device authorization revoked",
    txt_device_management: "Device Management",
    txt_device_removed: "Device removed",
    txt_disable_this_send: "Disable this send",
    txt_disable_totp: "Disable TOTP",
    txt_disable_totp_failed: "Disable TOTP failed",
    txt_download: "Download",
    txt_download_failed: "Download failed",
    txt_edge_browser: "Edge Browser",
    txt_edge_extension: "Edge Extension",
    txt_edit: "Edit",
    txt_edit_send: "Edit Send",
    txt_email: "Email",
    txt_email_password_and_recovery_code_are_required: "Email, password and recovery code are required",
    txt_enable_totp: "Enable TOTP",
    txt_enable_totp_failed: "Enable TOTP failed",
    txt_enabled: "Enabled",
    txt_encrypted_file: "Encrypted File",
    txt_encrypted_file_2: "Encrypted file",
    txt_enter_a_folder_name: "Enter a folder name.",
    txt_enter_master_password_to_disable_two_step_verification: "Enter master password to disable two-step verification.",
    txt_enter_master_password_to_view_this_item: "Enter master password to view this item.",
    txt_expiration_date: "Expiration Date",
    txt_expiration_days_0_never: "Expiration Days (0 = never)",
    txt_expires_at: "Expires At",
    txt_expires_at_value: "Expires at: {value}",
    txt_expiry: "Expiry",
    txt_expiry_month: "Expiry Month",
    txt_expiry_year: "Expiry Year",
    txt_failed_to_open_send: "Failed to open send",
    txt_favorite: "Favorite",
    txt_favorites: "Favorites",
    txt_field: "Field",
    txt_field_label: "Field Label",
    txt_field_label_is_required: "Field label is required.",
    txt_field_type: "Field Type",
    txt_field_value: "Field Value",
    txt_file: "File",
    txt_file_name: "File Name",
    txt_file_send: "File Send",
    txt_file_size: "File Size",
    txt_fingerprint: "Fingerprint",
    txt_firefox_browser: "Firefox Browser",
    txt_firefox_extension: "Firefox Extension",
    txt_first_name: "First Name",
    txt_folder: "Folder",
    txt_folder_created: "Folder created",
    txt_folder_name: "Folder Name",
    txt_folder_name_is_required: "Folder name is required",
    txt_folders: "Folders",
    txt_hidden: "Hidden",
    txt_hide: "Hide",
    txt_identity: "Identity",
    txt_identity_details: "Identity Details",
    txt_ie_browser: "IE Browser",
    txt_invite_code_optional: "Invite Code (Not required for the first account; required for all others)",
    txt_invite_created: "Invite created",
    txt_invite_revoked: "Invite revoked",
    txt_invite_validity_hours: "Invite validity (hours)",
    txt_invites: "Invites",
    txt_ios: "iOS",
    txt_item: "Item",
    txt_item_created: "Item created",
    txt_item_deleted: "Item deleted",
    txt_item_history: "Item History",
    txt_item_name_is_required: "Item name is required.",
    txt_item_updated: "Item updated",
    txt_last_edited_value: "Last edited: {value}",
    txt_last_name: "Last Name",
    txt_last_seen: "Last Seen",
    txt_license_number: "License Number",
    txt_link_copied: "Link copied",
    txt_linked: "Linked",
    txt_linux_desktop: "Linux Desktop",
    txt_loading: "Loading...",
    txt_loading_nodewarden: "Loading NodeWarden...",
    txt_jwt_warning_title: "Server Security Warning",
    txt_jwt_warning_subtitle: "JWT secret is not configured safely.",
    txt_jwt_title_missing: "JWT_SECRET is missing",
    txt_jwt_title_too_short: "JWT_SECRET is too short",
    txt_jwt_title_default: "JWT_SECRET is using the default value",
    txt_jwt_reason_missing: "JWT secret is missing.",
    txt_jwt_reason_default: "JWT secret is still the default/sample value.",
    txt_jwt_reason_too_short: "JWT secret is too short. Minimum length is {min}.",
    txt_jwt_how_to_fix_add: "How to add JWT_SECRET",
    txt_jwt_how_to_fix_replace: "How to replace JWT_SECRET",
    txt_jwt_add_step_1: "Use the 32-character generator below and copy a new key.",
    txt_jwt_add_step_2: "Cloudflare Dashboard -> Workers & Pages -> Your Service -> Settings -> Variables and Secrets, add JWT_SECRET.",
    txt_jwt_add_step_3: "Save and wait for redeploy, then refresh this page.",
    txt_jwt_replace_step_1: "Use the 32-character generator below and create a stronger key (minimum {min} characters).",
    txt_jwt_replace_step_2: "Cloudflare Dashboard -> Workers & Pages -> Your Service -> Settings -> Variables and Secrets, replace JWT_SECRET.",
    txt_jwt_replace_step_3: "Save and wait for redeploy, then refresh this page.",
    txt_how_to_fix: "How to fix",
    txt_jwt_fix_step_1: "Open your deployment environment variables.",
    txt_jwt_fix_step_2: "If your current key is not random enough, use the 32-character generator below.",
    txt_jwt_fix_step_3: "Cloudflare Dashboard -> Workers & Pages -> Your Service -> Settings -> Variables and Secrets, update JWT_SECRET.",
    txt_jwt_fix_step_4: "Save and wait for redeploy, then refresh this page to verify.",
    txt_random_secret_generator: "Random Secret Generator",
    txt_copied: "Copied",
    txt_log_in: "Log In",
    txt_log_out: "Log Out",
    txt_lock: "Lock",
    txt_login: "Login",
    txt_login_credentials: "Login Credentials",
    txt_login_failed: "Login failed",
    txt_login_success: "Login success",
    txt_macos_desktop: "macOS Desktop",
    txt_manage_authorized_devices_and_30_day_totp_trusted_sessions: "Manage authorized devices and 30-day TOTP trusted sessions.",
    txt_master_password: "Master Password",
    txt_master_password_changed_please_login_again: "Master password changed. Please login again.",
    txt_master_password_is_required: "Master password is required",
    txt_master_password_is_required_2: "Master password is required.",
    txt_master_password_must_be_at_least_12_chars: "Master password must be at least 12 chars",
    txt_master_password_reprompt: "Master password reprompt",
    txt_master_password_reprompt_2: "Master Password Reprompt",
    txt_max_access_count: "Max Access Count",
    txt_middle_name: "Middle Name",
    txt_move: "Move",
    txt_move_selected_items: "Move Selected Items",
    txt_moved_selected_items: "Moved selected items",
    txt_name: "Name",
    txt_name_is_required: "Name is required",
    txt_new_password: "New Password",
    txt_new_password_must_be_at_least_12_chars: "New password must be at least 12 chars",
    txt_new_passwords_do_not_match: "New passwords do not match",
    txt_new_send: "New Send",
    txt_next: "Next",
    txt_no: "No",
    txt_no_devices_found: "No devices found.",
    txt_no_folder: "No Folder",
    txt_no_items: "No items",
    txt_no_name: "(No Name)",
    txt_no_sends: "No sends",
    txt_nodewarden_send: "NodeWarden Send",
    txt_not_trusted: "Not trusted",
    txt_note: "Note",
    txt_notes: "Notes",
    txt_number: "Number",
    txt_open: "Open",
    txt_opera_browser: "Opera Browser",
    txt_opera_extension: "Opera Extension",
    txt_or: "or",
    txt_options: "Options",
    txt_passport_number: "Passport Number",
    txt_password: "Password",
    txt_password_is_already_verified: "Password is already verified.",
    txt_passwords_do_not_match: "Passwords do not match",
    txt_phone: "Phone",
    txt_please_input_email_and_password: "Please input email and password",
    txt_please_input_master_password: "Please input master password",
    txt_please_input_totp_code: "Please input TOTP code",
    txt_please_select_a_file: "Please select a file",
    txt_postal_code: "Postal Code",
    txt_prev: "Prev",
    txt_private_key: "Private Key",
    txt_profile: "Profile",
    txt_profile_unavailable: "Profile unavailable",
    txt_profile_updated: "Profile updated",
    txt_public_key: "Public Key",
    txt_recover_2fa_failed: "Recover 2FA failed",
    txt_recover_two_step_login: "Recover Two-step Login",
    txt_recovered_but_auto_login_failed_please_sign_in: "Recovered but auto-login failed, please sign in.",
    txt_recovery_code: "Recovery Code",
    txt_recovery_code_copied: "Recovery code copied",
    txt_recovery_code_is_empty: "Recovery code is empty",
    txt_recovery_code_loaded: "Recovery code loaded",
    txt_refresh: "Refresh",
    txt_refresh_in_seconds_s: "Refresh in {seconds}s",
    txt_regenerate: "Regenerate",
    txt_registration_succeeded_please_sign_in: "Registration succeeded. Please sign in.",
    txt_remove: "Remove",
    txt_remove_device: "Remove device",
    txt_remove_device_2: "Remove Device",
    txt_remove_device_name_and_clear_its_2fa_trust: "Remove device \"{name}\" and clear its 2FA trust?",
    txt_reveal: "Reveal",
    txt_revoke: "Revoke",
    txt_revoke_30_day_totp_trust_for_name: "Revoke 30-day TOTP trust for \"{name}\"?",
    txt_revoke_30_day_totp_trust_from_all_devices: "Revoke 30-day TOTP trust from all devices?",
    txt_revoke_all_trusted: "Revoke All Trusted",
    txt_revoke_all_trusted_devices: "Revoke all trusted devices",
    txt_revoke_device_authorization: "Revoke device authorization",
    txt_revoke_trust: "Revoke Trust",
    txt_role: "Role",
    txt_save: "Save",
    txt_save_profile: "Save Profile",
    txt_save_profile_failed: "Save profile failed",
    txt_search_sends: "Search sends...",
    txt_search_your_secure_vault: "Search your secure vault...",
    txt_secret_and_code_are_required: "Secret and code are required",
    txt_secret_copied: "Secret copied",
    txt_secure_note: "Secure Note",
    txt_security_code: "Security Code",
    txt_security_code_cvv: "Security Code (CVV)",
    txt_select_all: "Select All",
    txt_select_an_item: "Select an item",
    txt_send_created: "Send created",
    txt_send_deleted: "Send deleted",
    txt_send_details: "Send Details",
    txt_send_file: "send-file",
    txt_send_unavailable: "Send unavailable.",
    txt_send_updated: "Send updated",
    txt_sign_out: "Sign Out",
    txt_ssh_key: "SSH Key",
    txt_ssn: "SSN",
    txt_state_province: "State / Province",
    txt_status: "Status",
    txt_submit: "Submit",
    txt_sync: "Sync",
    txt_sync_vault: "Sync Vault",
    txt_dash: "-",
    txt_text: "Text",
    txt_text_2fa_recovered: "2FA recovered",
    txt_text_2fa_recovered_new_recovery_code_code: "2FA recovered. New recovery code: {code}",
    txt_text_3: "------",
    txt_text_is_required: "Text is required",
    txt_text_send: "Text Send",
    txt_this_is_a_one_time_code_after_it_is_used_a_new_code_is_generated_automatically: "This is a one-time code. After it is used, a new code is generated automatically.",
    txt_this_item_requires_master_password_every_time_before_viewing_details: "This item requires master password every time before viewing details.",
    txt_this_link_is_missing_decryption_key: "This link is missing decryption key.",
    txt_this_send_is_password_protected: "This send is password protected.",
    txt_title: "Title",
    txt_totp: "TOTP",
    txt_totp_code: "TOTP Code",
    txt_totp_disabled: "TOTP disabled",
    txt_totp_enabled: "TOTP enabled",
    txt_totp_is_enabled_for_this_account: "TOTP is enabled for this account.",
    txt_totp_secret: "TOTP Secret",
    txt_totp_verify_failed: "TOTP verify failed",
    txt_passkey: "Passkey",
    txt_passkey_created_at_value: "Created at {value}",
    txt_attachments: "Attachments",
    txt_upload_attachments: "Upload attachments",
    txt_new_attachments: "New attachments",
    txt_marked_for_removal_count: "{count} attachment(s) will be removed on save",
    txt_trash: "Trash",
    txt_trust_this_device_for_30_days: "Trust this device for 30 days",
    txt_trusted_until: "Trusted Until",
    txt_two_step_verification: "Two-step verification",
    txt_type: "Type",
    txt_type_type: "Type {type}",
    txt_unban: "Unban",
    txt_unchecked: "Unchecked",
    txt_unknown_device: "Unknown device",
    txt_unlock: "Unlock",
    txt_unlock_details: "Unlock Details",
    txt_unlock_failed: "Unlock failed",
    txt_unlock_failed_master_password_is_incorrect: "Unlock failed. Master password is incorrect.",
    txt_unlock_item: "Unlock Item",
    txt_unlock_send: "Unlock Send",
    txt_unlock_vault: "Unlock Vault",
    txt_unlocked: "Unlocked",
    txt_update_item_failed: "Update item failed",
    txt_update_send_failed: "Update send failed",
    txt_use_recovery_code: "Use Recovery Code",
    txt_use_your_one_time_recovery_code_to_disable_two_step_verification: "Use your one-time recovery code to disable two-step verification.",
    txt_user_deleted: "User deleted",
    txt_user_status_updated: "User status updated",
    txt_username: "Username",
    txt_users: "Users",
    txt_vault_synced: "Vault synced",
    txt_verification_code: "Verification Code",
    txt_verify: "Verify",
    txt_view_recovery_code: "View Recovery Code",
    txt_web: "Web",
    txt_website: "Website",
    txt_websites: "Websites",
    txt_windows_desktop: "Windows Desktop",
    txt_yes: "Yes",
  },
  'zh-CN': {},
};

const zhCNOverrides: Record<string, string> = {
  nav_my_vault: '我的保险库',
  nav_sends: 'Send',
  nav_admin_panel: '用户管理',
  nav_account_settings: '账户设置',
  nav_device_management: '设备管理',
  nav_backup_strategy: '备份策略',
  nav_import_export: '导入导出',
  backup_strategy_title: '备份策略',
  backup_strategy_under_construction: '正在搭建中',
  import_export_title: '导入导出',
  import_export_under_construction: '正在搭建中',
  txt_sign_out: '退出登录',
  txt_log_in: '登录',
  txt_log_out: '退出',
  txt_create_account: '创建账户',
  txt_back_to_login: '返回登录',
  txt_unlock: '解锁',
  txt_unlock_vault: '解锁保险库',
  txt_master_password: '主密码',
  txt_email: '邮箱',
  txt_name: '名称',
  txt_password: '密码',
  txt_confirm_password: '确认密码',
  txt_confirm_master_password: '确认主密码',
  txt_submit: '提交',
  txt_cancel: '取消',
  txt_yes: '是',
  txt_no: '否',
  txt_loading: '加载中...',
  txt_loading_nodewarden: '正在加载 NodeWarden...',
  txt_search_sends: '搜索发送...',
  txt_search_your_secure_vault: '搜索你的保险库...',
  txt_refresh: '刷新',
  txt_sync: '同步',
  txt_sync_vault: '同步',
  txt_add: '新增',
  txt_edit: '编辑',
  txt_delete: '删除',
  txt_save: '保存',
  txt_confirm: '确认',
  txt_move: '移动',
  txt_copy: '复制',
  txt_copy_link: '复制链接',
  txt_select_all: '全选',
  txt_delete_selected: '删除所选',
  txt_all_items: '所有项目',
  txt_favorites: '收藏',
  txt_trash: '回收站',
  txt_folder: '文件夹',
  txt_folders: '文件夹',
  txt_no_folder: '无文件夹',
  txt_no_items: '没有项目',
  txt_no_sends: '没有发送',
  txt_select_an_item: '请选择一个项目',
  txt_login: '登录',
  txt_card: '银行卡',
  txt_identity: '身份',
  txt_note: '笔记',
  txt_secure_note: '安全笔记',
  txt_ssh_key: 'SSH 密钥',
  txt_login_credentials: '登录信息',
  txt_card_details: '银行卡详情',
  txt_identity_details: '身份详情',
  txt_autofill_options: '自动填充选项',
  txt_additional_options: '附加选项',
  txt_custom_fields: '自定义字段',
  txt_notes: '备注',
  txt_item_history: '项目历史',
  txt_last_edited_value: '最后编辑：{value}',
  txt_created_value: '创建于：{value}',
  txt_username: '用户名',
  txt_website: '网站',
  txt_websites: '网站',
  txt_open: '打开',
  txt_hide: '隐藏',
  txt_reveal: '显示',
  txt_favorite: '收藏',
  txt_field: '字段',
  txt_field_type: '字段类型',
  txt_field_label: '字段标签',
  txt_field_value: '字段值',
  txt_add_field: '添加字段',
  txt_remove: '移除',
  txt_enabled: '已启用',
  txt_checked: '已勾选',
  txt_unchecked: '未勾选',
  txt_profile: '资料',
  txt_save_profile: '保存资料',
  txt_change_master_password: '修改主密码',
  txt_current_password: '当前密码',
  txt_new_password: '新密码',
  txt_change_password: '修改密码',
  txt_totp: 'TOTP',
  txt_enable_totp: '启用 TOTP',
  txt_disable_totp: '停用 TOTP',
  txt_totp_code: 'TOTP 验证码',
  txt_totp_secret: 'TOTP 密钥',
  txt_verification_code: '验证码',
  txt_recovery_code: '恢复代码',
  txt_view_recovery_code: '查看恢复代码',
  txt_copy_code: '复制代码',
  txt_device_management: '设备管理',
  txt_authorized_devices: '已授权设备',
  txt_device: '设备',
  txt_last_seen: '最后在线',
  txt_trusted_until: '信任至',
  txt_revoke_trust: '撤销信任',
  txt_remove_device_2: '移除设备',
  txt_not_trusted: '未信任',
  txt_unknown_device: '未知设备',
  txt_users: '用户',
  txt_invites: '邀请码',
  txt_ban: '封禁',
  txt_unban: '解封',
  txt_create_timed_invite: '创建时效邀请码',
  txt_invite_validity_hours: '邀请码有效期（小时）',
  txt_delete_all: '全部删除',
  txt_prev: '上一页',
  txt_next: '下一页',
  txt_send_details: '发送详情',
  txt_new_send: '新建发送',
  txt_edit_send: '编辑发送',
  txt_file_send: '文件发送',
  txt_text_send: '文本发送',
  txt_file: '文件',
  txt_text: '文本',
  txt_file_name: '文件名',
  txt_file_size: '文件大小',
  txt_access_count: '访问次数',
  txt_deletion_date: '删除日期',
  txt_expiration_date: '过期日期',
  txt_deletion_days: '删除天数',
  txt_expiration_days_0_never: '过期天数（0 表示不过期）',
  txt_max_access_count: '最大访问次数',
  txt_options: '选项',
  txt_disable_this_send: '禁用此发送',
  txt_auto_copy_link_after_save: '保存后自动复制链接',
  txt_unlock_send: '解锁发送',
  txt_nodewarden_send: 'NodeWarden 发送',
  txt_send_unavailable: '发送不可用。',
  txt_download: '下载',
  txt_expires_at: '过期时间',
  txt_expires_at_value: '过期于：{value}',
  txt_dash: '-',
  txt_or: '或',
  txt_no_name: '（无名称）',
  txt_are_you_sure_you_want_to_log_out: '确认要退出登录吗？',
  txt_delete_item: '删除项目',
  txt_delete_selected_items: '删除所选项目',
  txt_move_selected_items: '移动所选项目',
  txt_create_folder: '创建文件夹',
  txt_folder_name: '文件夹名称',
  txt_unlock_item: '解锁项目',
  txt_use_recovery_code: '使用恢复代码',
  txt_two_step_verification: '两步验证',
  txt_recover_two_step_login: '恢复两步登录',
  txt_title: '称谓',
  txt_first_name: '名',
  txt_middle_name: '中间名',
  txt_last_name: '姓',
  txt_company: '公司',
  txt_ssn: '社保号',
  txt_passport_number: '护照号',
  txt_license_number: '证件号',
  txt_private_key: '私钥',
  txt_public_key: '公钥',
  txt_fingerprint: '指纹',
  txt_master_password_reprompt: '主密码二次确认',
  txt_master_password_reprompt_2: '主密码二次确认',
  txt_configure_custom_field_values: '配置自定义字段值。',
  txt_hidden: '隐藏',
  txt_boolean: '布尔',
  txt_regenerate: '重新生成',
  txt_copy_secret: '复制密钥',
  txt_this_is_a_one_time_code_after_it_is_used_a_new_code_is_generated_automatically: '这是一次性恢复代码，使用后将自动生成新的恢复代码。',
  txt_manage_authorized_devices_and_30_day_totp_trusted_sessions: '管理已授权设备和 30 天 TOTP 受信会话。',
  txt_role: '角色',
  txt_status: '状态',
  txt_actions: '操作',
  txt_type: '类型',
  txt_revoke_all_trusted: '撤销全部受信任设备',
  txt_revoke_all_trusted_devices: '撤销所有受信任设备',
  txt_revoke_30_day_totp_trust_from_all_devices: '确认撤销所有设备的 30 天 TOTP 信任吗？',
  txt_revoke_30_day_totp_trust_for_name: '确认撤销“{name}”的 30 天 TOTP 信任吗？',
  txt_remove_device_name_and_clear_its_2fa_trust: '确认移除设备“{name}”并清除其 2FA 信任吗？',
  txt_role_admin: '管理员',
  txt_role_user: '用户',
  txt_status_active: '正常',
  txt_status_banned: '已封禁',
  txt_status_inactive: '未激活',
  txt_accessed_count_times: '已访问 {count} 次',
  txt_add_website: '添加网站',
  txt_added: '已添加',
  txt_address: '地址',
  txt_address_1: '地址 1',
  txt_address_2: '地址 2',
  txt_address_3: '地址 3',
  txt_all_device_authorizations_revoked: '已撤销所有设备授权',
  txt_all_invites_deleted: '已删除所有邀请码',
  txt_all_sends: '所有发送',
  txt_android: '安卓',
  txt_are_you_sure_you_want_to_delete_count_selected_items: '确认删除所选的 {count} 个项目？',
  txt_are_you_sure_you_want_to_delete_this_item: '确认删除此项目？',
  txt_authenticator_key: '验证器密钥',
  txt_brand: '品牌',
  txt_bulk_delete_failed: '批量删除失败',
  txt_bulk_delete_sends_failed: '批量删除发送失败',
  txt_bulk_move_failed: '批量移动失败',
  txt_cardholder_name: '持卡人姓名',
  txt_change_password_failed: '修改密码失败',
  txt_choose_destination_folder: '选择目标文件夹。',
  txt_chrome_browser: 'Chrome 浏览器',
  txt_chrome_extension: 'Chrome 扩展',
  txt_city_town: '城市 / 城镇',
  txt_code: '代码',
  txt_country: '国家',
  txt_create: '创建',
  txt_create_folder_failed: '创建文件夹失败',
  txt_create_item_failed: '创建项目失败',
  txt_create_send_failed: '创建发送失败',
  txt_current_new_password_is_required: '需要输入当前密码和新密码',
  txt_decrypt_failed: '（解密失败）',
  txt_decrypt_failed_2: '解密失败',
  txt_delete_all_invite_codes_active_inactive: '删除所有邀请码（有效/无效）？',
  txt_delete_all_invites: '删除所有邀请码',
  txt_delete_item_failed: '删除项目失败',
  txt_delete_send_failed: '删除发送失败',
  txt_delete_this_user_and_all_user_data: '删除此用户及其所有数据？',
  txt_delete_user: '删除用户',
  txt_deleted_selected_items: '已删除所选项目',
  txt_deleted_selected_sends: '已删除所选发送',
  txt_device_authorization_revoked: '已撤销设备授权',
  txt_device_removed: '设备已移除',
  txt_disable_totp_failed: '禁用 TOTP 失败',
  txt_download_failed: '下载失败',
  txt_edge_browser: 'Edge 浏览器',
  txt_edge_extension: 'Edge 扩展',
  txt_email_password_and_recovery_code_are_required: '需要输入邮箱、密码和恢复代码',
  txt_enable_totp_failed: '启用 TOTP 失败',
  txt_encrypted_file: '加密文件',
  txt_encrypted_file_2: '加密文件',
  txt_enter_a_folder_name: '请输入文件夹名称',
  txt_enter_master_password_to_disable_two_step_verification: '输入主密码以禁用两步验证',
  txt_enter_master_password_to_view_this_item: '输入主密码以查看此项目',
  txt_expiry: '有效期',
  txt_expiry_month: '有效期月',
  txt_expiry_year: '有效期年',
  txt_failed_to_open_send: '打开发送失败',
  txt_field_label_is_required: '字段标签不能为空',
  txt_firefox_browser: 'Firefox 浏览器',
  txt_firefox_extension: 'Firefox 扩展',
  txt_folder_created: '文件夹已创建',
  txt_folder_name_is_required: '文件夹名称不能为空',
  txt_ie_browser: 'IE 浏览器',
  txt_invite_code_optional: '邀请码（首位注册者无需填写，其他人必填）',
  txt_invite_created: '邀请码已创建',
  txt_invite_revoked: '邀请码已撤销',
  txt_ios: 'iOS',
  txt_item: '项目',
  txt_item_created: '项目已创建',
  txt_item_deleted: '项目已删除',
  txt_item_name_is_required: '项目名称不能为空',
  txt_item_updated: '项目已更新',
  txt_link_copied: '链接已复制',
  txt_linked: '已关联',
  txt_linux_desktop: 'Linux 桌面端',
  txt_login_failed: '登录失败',
  txt_login_success: '登录成功',
  txt_macos_desktop: 'macOS 桌面端',
  txt_master_password_changed_please_login_again: '主密码已修改，请重新登录',
  txt_master_password_is_required: '主密码不能为空',
  txt_master_password_is_required_2: '请输入主密码',
  txt_master_password_must_be_at_least_12_chars: '主密码至少需要 12 个字符',
  txt_moved_selected_items: '已移动所选项目',
  txt_name_is_required: '名称不能为空',
  txt_new_password_must_be_at_least_12_chars: '新密码至少需要 12 个字符',
  txt_new_passwords_do_not_match: '两次输入的新密码不一致',
  txt_no_devices_found: '未找到设备',
  txt_number: '数字',
  txt_opera_browser: 'Opera 浏览器',
  txt_opera_extension: 'Opera 扩展',
  txt_password_is_already_verified: '密码已验证',
  txt_passwords_do_not_match: '两次输入的密码不一致',
  txt_phone: '电话',
  txt_please_input_email_and_password: '请输入邮箱和密码',
  txt_please_input_master_password: '请输入主密码',
  txt_please_input_totp_code: '请输入 TOTP 验证码',
  txt_please_select_a_file: '请选择文件',
  txt_postal_code: '邮政编码',
  txt_profile_unavailable: '资料不可用',
  txt_profile_updated: '资料已更新',
  txt_recover_2fa_failed: '恢复 2FA 失败',
  txt_recovered_but_auto_login_failed_please_sign_in: '已恢复，但自动登录失败，请手动登录',
  txt_recovery_code_copied: '恢复代码已复制',
  txt_recovery_code_is_empty: '恢复代码为空',
  txt_recovery_code_loaded: '恢复代码已加载',
  txt_refresh_in_seconds_s: '{seconds} 秒后刷新',
  txt_registration_succeeded_please_sign_in: '注册成功，请登录',
  txt_remove_device: '移除设备',
  txt_revoke: '撤销',
  txt_revoke_device_authorization: '撤销设备授权',
  txt_save_profile_failed: '保存资料失败',
  txt_secret_and_code_are_required: '密钥和代码不能为空',
  txt_secret_copied: '密钥已复制',
  txt_security_code: '安全码',
  txt_security_code_cvv: '安全码 (CVV)',
  txt_send_created: '发送已创建',
  txt_send_deleted: '发送已删除',
  txt_send_file: '发送文件',
  txt_send_updated: '发送已更新',
  txt_state_province: '省 / 州',
  txt_text_2fa_recovered: '2FA 已恢复',
  txt_text_2fa_recovered_new_recovery_code_code: '2FA 已恢复，新的恢复代码：{code}',
  txt_text_3: '------',
  txt_text_is_required: '文本不能为空',
  txt_this_item_requires_master_password_every_time_before_viewing_details: '每次查看详情前均需输入主密码',
  txt_this_link_is_missing_decryption_key: '此链接缺少解密密钥',
  txt_this_send_is_password_protected: '此发送受密码保护',
  txt_totp_disabled: 'TOTP 已禁用',
  txt_totp_enabled: 'TOTP 已启用',
  txt_totp_is_enabled_for_this_account: '此账户已启用 TOTP。',
  txt_totp_verify_failed: 'TOTP 验证失败',
  txt_trust_this_device_for_30_days: '信任此设备 30 天',
  txt_type_type: '类型 {type}',
  txt_unlock_details: '解锁详情',
  txt_unlock_failed: '解锁失败',
  txt_unlock_failed_master_password_is_incorrect: '解锁失败，主密码不正确。',
  txt_unlocked: '已解锁',
  txt_update_item_failed: '更新项目失败',
  txt_update_send_failed: '更新发送失败',
  txt_use_your_one_time_recovery_code_to_disable_two_step_verification: '使用一次性恢复代码禁用两步验证。',
  txt_user_deleted: '用户已删除',
  txt_user_status_updated: '用户状态已更新',
  txt_vault_synced: '保险库已同步',
  txt_verify: '验证',
  txt_web: '网页',
  txt_windows_desktop: 'Windows 桌面端',
  txt_jwt_warning_title: 'JWT_SECRET 配置警告',
  txt_jwt_warning_subtitle: 'JWT 密钥当前不安全，请先修复后再继续。',
  txt_jwt_title_missing: '未检测到 JWT_SECRET',
  txt_jwt_title_too_short: 'JWT_SECRET 长度过短',
  txt_jwt_title_default: 'JWT_SECRET使用默认值',
  txt_jwt_reason_missing: '未检测到 JWT_SECRET。',
  txt_jwt_reason_default: 'JWT_SECRET 仍在使用默认示例值。',
  txt_jwt_reason_too_short: 'JWT_SECRET 长度过短，至少需要 {min} 位。',
  txt_jwt_how_to_fix_add: '处理步骤（添加 JWT_SECRET）',
  txt_jwt_how_to_fix_replace: '处理步骤（更换 JWT_SECRET）',
  txt_jwt_add_step_1: '使用下方 32 位随机生成器，复制一个新密钥。',
  txt_jwt_add_step_2: '到 Cloudflare 控制台 -> Workers 和 Pages -> 你的服务 -> 设置 -> 变量和机密，新增 JWT_SECRET。',
  txt_jwt_add_step_3: '保存并等待重新部署完成，然后刷新本页确认。',
  txt_jwt_replace_step_1: '使用下方 32 位随机生成器，生成更强的密钥（至少 {min} 位）。',
  txt_jwt_replace_step_2: '到 Cloudflare 控制台 -> Workers 和 Pages -> 你的服务 -> 设置 -> 变量和机密，替换 JWT_SECRET。',
  txt_jwt_replace_step_3: '保存并等待重新部署完成，然后刷新本页确认。',
  txt_how_to_fix: '处理步骤（添加 / 更换）',
  txt_jwt_fix_step_1: '你可以继续下一步，不影响使用。',
  txt_jwt_fix_step_2: '如果当前密钥不是强随机值，建议使用下方 32 位生成器。',
  txt_jwt_fix_step_3: '到 Cloudflare 控制台 -> Workers 和 Pages -> 你的服务 -> 设置 -> 变量和机密，更新 JWT_SECRET。',
  txt_jwt_fix_step_4: '保存并等待重新部署完成，然后刷新本页确认。',
  txt_random_secret_generator: '随机密钥生成器',
  txt_copied: '已复制',
};

zhCNOverrides.txt_lock = '锁定';
zhCNOverrides.txt_passkey = 'Passkey';
zhCNOverrides.txt_passkey_created_at_value = '创建于 {value}';
zhCNOverrides.txt_attachments = '附件';
zhCNOverrides.txt_upload_attachments = '上传附件';
zhCNOverrides.txt_new_attachments = '待上传附件';
zhCNOverrides.txt_marked_for_removal_count = '保存后将删除 {count} 个附件';
messages.en.txt_import = 'Import';
messages.en.txt_export = 'Export';
messages.en.txt_format = 'Format';
messages.en.txt_source_file = 'Source file';
messages.en.txt_folder_handling = 'Folder handling';
messages.en.txt_import_folder_mode_original = 'Original path from import file';
messages.en.txt_import_folder_mode_none = 'No folder';
messages.en.txt_import_folder_mode_target = 'One selected folder';
messages.en.txt_target_folder = 'Target folder';
messages.en.txt_select_folder_placeholder = '-- Select folder --';
messages.en.txt_import_vault_data_hint = 'Import vault data into your current account.';
messages.en.txt_export_vault_data_hint = 'Export vault data from your current account.';
messages.en.txt_import_export_title = 'Import & Export';
messages.en.txt_import_export_feature_intro = 'Provides standardized vault migration across clients, including attachment-aware and encrypted workflows.';
messages.en.txt_import_export_feature_bw_zip_title = 'Bitwarden vault + attachments ZIP';
messages.en.txt_import_export_feature_bw_zip_desc = 'Supports both import and export for Bitwarden ZIP archives containing vault data and attachments.';
messages.en.txt_import_export_feature_nodewarden_json_title = 'NodeWarden vault + attachments JSON';
messages.en.txt_import_export_feature_nodewarden_json_desc = 'Supports NodeWarden JSON import/export with vault and attachment payloads in a single document. Exported vault data remains importable by Bitwarden clients.';
messages.en.txt_import_export_feature_compat_title = 'Cross-client compatibility';
messages.en.txt_import_export_feature_compat_desc = 'Supports Bitwarden JSON/CSV and mainstream migration formats with consistent field normalization and import mapping.';
messages.en.txt_encrypted_mode = 'Encrypted mode';
messages.en.txt_account_verification = 'Account verification';
messages.en.txt_password_verification = 'Password verification';
messages.en.txt_file_password = 'File password';
messages.en.txt_zip_password_optional = 'ZIP password (optional)';
messages.en.txt_zip_password = 'ZIP password';
messages.en.txt_close = 'Close';
messages.en.txt_total = 'Total';
messages.en.txt_import_success = 'Import successful';
messages.en.txt_import_success_number_of_items = 'Imported {count} item(s) in total.';
messages.en.txt_import_file_password_required = 'Please enter file password.';
messages.en.txt_import_invalid_zip_password = 'Invalid ZIP password.';
messages.en.txt_export_completed = 'Export completed';
messages.en.txt_export_failed = 'Export failed';
messages.en.txt_import_invalid_password_protected_file = 'Invalid password-protected export file.';
messages.en.txt_import_decrypt_failed = 'Failed to decrypt import file.';
messages.en.txt_import_empty_zip_archive = 'Empty zip archive.';
messages.en.txt_import_no_json_found_in_zip = 'No importable JSON data found in zip archive.';
messages.en.txt_import_data_json_not_found = 'data.json not found in zip archive.';
messages.en.txt_import_zip_password_required = 'ZIP password is required.';
messages.en.txt_import_invalid_json_file = 'Invalid JSON file';
messages.en.txt_import_failed = 'Import failed';
messages.en.txt_import_encrypted_file_title = 'Import encrypted file';
messages.en.txt_import_encrypted_file_message = 'This Bitwarden export is password-protected. Enter the export file password to continue.';
messages.en.txt_import_encrypted_zip_title = 'Import encrypted ZIP';
messages.en.txt_import_encrypted_zip_message = 'This ZIP archive is password-protected. Enter the ZIP password to continue.';
messages.en.txt_new_type_header = 'New {type}';
messages.en.txt_edit_type_header = 'Edit {type}';
messages.en.txt_delete_folder = 'Delete Folder';
messages.en.txt_delete_folder_message = 'Delete folder "{name}"? Items inside will move to No Folder.';
messages.en.txt_folder_not_found = 'Folder not found';
messages.en.txt_folder_deleted = 'Folder deleted';
messages.en.txt_delete_folder_failed = 'Delete folder failed';
messages.en.txt_other = 'Other';
messages.en.txt_vault_key_unavailable = 'Vault key unavailable. Please unlock vault and try again.';
messages.en.txt_vault_not_ready = 'Vault is not ready yet';
messages.en.txt_unsupported_export_format = 'Unsupported export format';
messages.en.txt_invalid_encrypted_export = 'Invalid encrypted export file.';
messages.en.txt_export_belongs_to_another_account = 'This encrypted export belongs to another account.';
messages.en.txt_invalid_argon2id_params = 'Invalid Argon2id parameters in export file.';
messages.en.txt_unsupported_kdf_type = 'Unsupported kdfType: {type}';
messages.en.txt_invalid_file_password = 'Invalid file password.';
messages.en.txt_failed_to_map_attachments = 'Failed to map {count} attachment(s) to imported items.';

zhCNOverrides.txt_import = '导入';
zhCNOverrides.txt_export = '导出';
zhCNOverrides.txt_format = '格式';
zhCNOverrides.txt_source_file = '源文件';
zhCNOverrides.txt_folder_handling = '文件夹处理';
zhCNOverrides.txt_import_folder_mode_original = '保留导入文件中的原始路径';
zhCNOverrides.txt_import_folder_mode_none = '不使用文件夹';
zhCNOverrides.txt_import_folder_mode_target = '导入到指定文件夹';
zhCNOverrides.txt_target_folder = '目标文件夹';
zhCNOverrides.txt_select_folder_placeholder = '-- 选择文件夹 --';
zhCNOverrides.txt_import_vault_data_hint = '将数据导入到当前账号。';
zhCNOverrides.txt_export_vault_data_hint = '从当前账号导出数据。';
zhCNOverrides.txt_encrypted_mode = '加密方式';
zhCNOverrides.txt_account_verification = '账号验证';
zhCNOverrides.txt_password_verification = '密码验证';
zhCNOverrides.txt_file_password = '文件密码';
zhCNOverrides.txt_zip_password_optional = 'ZIP 密码（可选）';
zhCNOverrides.txt_zip_password = 'ZIP 密码';
zhCNOverrides.txt_close = '关闭';
zhCNOverrides.txt_total = '总计';
zhCNOverrides.txt_import_success = '数据导入成功';
zhCNOverrides.txt_import_success_number_of_items = '一共导入了 {count} 个项目。';
zhCNOverrides.txt_import_file_password_required = '请输入文件密码。';
zhCNOverrides.txt_import_invalid_zip_password = 'ZIP 密码错误。';
zhCNOverrides.txt_export_completed = '导出完成';
zhCNOverrides.txt_export_failed = '导出失败';
zhCNOverrides.txt_import_invalid_password_protected_file = '密码保护导出文件格式无效。';
zhCNOverrides.txt_import_decrypt_failed = '导入文件解密失败。';
zhCNOverrides.txt_import_empty_zip_archive = 'ZIP 压缩包为空。';
zhCNOverrides.txt_import_no_json_found_in_zip = 'ZIP 内未找到可导入的 JSON 数据。';
zhCNOverrides.txt_import_data_json_not_found = 'ZIP 内未找到 data.json。';
zhCNOverrides.txt_import_zip_password_required = '该 ZIP 需要密码。';
zhCNOverrides.txt_import_invalid_json_file = 'JSON 文件无效';
zhCNOverrides.txt_import_failed = '导入失败';
zhCNOverrides.txt_import_encrypted_file_title = '导入加密文件';
zhCNOverrides.txt_import_encrypted_file_message = '该 Bitwarden 导出文件已加密，请输入文件密码继续。';
zhCNOverrides.txt_import_encrypted_zip_title = '导入加密 ZIP';
zhCNOverrides.txt_import_encrypted_zip_message = '该 ZIP 压缩包已加密，请输入 ZIP 密码继续。';

zhCNOverrides.txt_import_export_title = '导入导出';
zhCNOverrides.txt_import_export_feature_intro = '提供标准化的数据迁移能力，覆盖附件与加密场景。';
zhCNOverrides.txt_import_export_feature_bw_zip_title = 'Bitwarden 密码库 + 附件 ZIP';
zhCNOverrides.txt_import_export_feature_bw_zip_desc = '支持导入与导出包含密码库和附件的 Bitwarden ZIP 压缩包。';
zhCNOverrides.txt_import_export_feature_nodewarden_json_title = 'NodeWarden 密码库 + 附件 JSON';
zhCNOverrides.txt_import_export_feature_nodewarden_json_desc = '支持 NodeWarden JSON 导入导出，单文件包含密码库与附件；导出的密码库数据可被 Bitwarden 客户端导入。';
zhCNOverrides.txt_import_export_feature_compat_title = '跨客户端兼容';
zhCNOverrides.txt_import_export_feature_compat_desc = '支持 Bitwarden JSON/CSV 与主流迁移格式，统一字段映射与导入行为。';
zhCNOverrides.txt_new_type_header = '新建{type}';
zhCNOverrides.txt_edit_type_header = '编辑{type}';
zhCNOverrides.txt_delete_folder = '删除文件夹';
zhCNOverrides.txt_delete_folder_message = '删除文件夹「{name}」？其中的项目将移至无文件夹。';
zhCNOverrides.txt_folder_not_found = '文件夹不存在';
zhCNOverrides.txt_folder_deleted = '文件夹已删除';
zhCNOverrides.txt_delete_folder_failed = '删除文件夹失败';
zhCNOverrides.txt_other = '其他';
zhCNOverrides.txt_vault_key_unavailable = '账户密钥不可用，请先解锁保险库后重试。';
zhCNOverrides.txt_vault_not_ready = '保险库数据尚未就绪';
zhCNOverrides.txt_unsupported_export_format = '不支持的导出格式';
zhCNOverrides.txt_invalid_encrypted_export = '加密导出文件无效。';
zhCNOverrides.txt_export_belongs_to_another_account = '此加密导出文件属于另一个账号。';
zhCNOverrides.txt_invalid_argon2id_params = '导出文件中的 Argon2id 参数无效。';
zhCNOverrides.txt_unsupported_kdf_type = '不支持的 KDF 类型：{type}';
zhCNOverrides.txt_invalid_file_password = '文件密码错误。';
zhCNOverrides.txt_failed_to_map_attachments = '无法将 {count} 个附件匹配到导入项目。';

messages['zh-CN'] = { ...messages.en, ...zhCNOverrides };

function resolveInitialLocale(): Locale {
  try {
    const saved = localStorage.getItem(LOCALE_STORAGE_KEY);
    if (saved === 'en' || saved === 'zh-CN') return saved;
  } catch {
    // ignore storage errors
  }
  if (typeof navigator !== 'undefined') {
    const langs = Array.isArray(navigator.languages) ? navigator.languages : [navigator.language];
    for (const lang of langs) {
      if (String(lang || '').toLowerCase().startsWith('zh')) return 'zh-CN';
    }
  }
  return 'en';
}

let locale: Locale = resolveInitialLocale();

export type I18nParams = Record<string, string | number | null | undefined>;

export function t(key: string, params?: I18nParams): string {
  const template = messages[locale][key] ?? key;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (_, name: string) => String(params[name] ?? ''));
}

export function getLocale(): Locale {
  return locale;
}

export function setLocale(next: Locale): void {
  locale = next;
  try {
    localStorage.setItem(LOCALE_STORAGE_KEY, next);
  } catch {
    // ignore storage errors
  }
}


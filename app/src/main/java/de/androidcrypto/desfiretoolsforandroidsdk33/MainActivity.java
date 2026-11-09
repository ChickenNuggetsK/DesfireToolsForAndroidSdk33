package de.androidcrypto.desfiretoolsforandroidsdk33;

import static com.github.skjolber.desfire.libfreefare.MifareDesfire.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.FragmentManager;
import android.app.FragmentTransaction;
import android.content.BroadcastReceiver;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

import com.github.skjolber.desfire.ev1.model.DesfireApplication;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationId;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKey;
import com.github.skjolber.desfire.ev1.model.DesfireApplicationKeySettings;
import com.github.skjolber.desfire.ev1.model.DesfireTag;
import com.github.skjolber.desfire.ev1.model.VersionInfo;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepAdapter;
import com.github.skjolber.desfire.ev1.model.command.DefaultIsoDepWrapper;
import com.github.skjolber.desfire.ev1.model.command.Utils;
import com.github.skjolber.desfire.ev1.model.file.DesfireFile;
import com.github.skjolber.desfire.ev1.model.file.RecordDesfireFile;
import com.github.skjolber.desfire.ev1.model.file.StandardDesfireFile;
import com.github.skjolber.desfire.ev1.model.file.ValueDesfireFile;
import com.github.skjolber.desfire.ev1.model.key.Desfire3DESKey;
import com.github.skjolber.desfire.ev1.model.key.Desfire3K3DESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireAESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireDESKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireKey;
import com.github.skjolber.desfire.ev1.model.key.DesfireKeyType;
import com.github.skjolber.desfire.libfreefare.MifareDESFireKey;
import com.github.skjolber.desfire.libfreefare.MifareDesfireKey1;
import com.github.skjolber.desfire.libfreefare.MifareTag;

import de.androidcrypto.desfiretoolsforandroidsdk33.filelist.ApplicationDetail;
import de.androidcrypto.desfiretoolsforandroidsdk33.filelist.ApplicationDetailApplicationKey;
import de.androidcrypto.desfiretoolsforandroidsdk33.filelist.ApplicationDetailFile;
import de.androidcrypto.desfiretoolsforandroidsdk33.filelist.ApplicationDetailKey;
import de.androidcrypto.desfiretoolsforandroidsdk33.filelist.ApplicationDetailRecord;
import de.androidcrypto.desfiretoolsforandroidsdk33.keys.DataSource;


@SuppressLint("ResourceAsColor")
public class MainActivity extends Activity implements ReaderCallback, FragmentManager.OnBackStackChangedListener, FileSaveFragment.Callbacks {

    private static final String ACTION_NFC_SETTINGS = "android.settings.NFC_SETTINGS";
    
    /** this action seems never to be emitted, but is here for future use */
    private static final String ACTION_TAG_LEFT_FIELD = "android.nfc.action.TAG_LOST";

	public static byte[] key_data_aes  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	public static final byte key_data_aes_version = 0x42;

	private static final String TAG = MainActivity.class.getName();
	
	private interface OnKeyListener {
		void onKey(DesfireKey key);
	}

	private interface OnKeyNumberListener {
		void onKeyNumber(int index, String access);
	}

	private NfcAdapter nfcAdapter;
	private List<DesfireApplication> applications;
	
	private DesfireApplication application;
	
	private DesfireApplicationKey authenticatedKey;
	
	private MifareTag tag;
	private DesfireTag desfireTag;
	private DefaultIsoDepAdapter defaultIsoDepAdapter;

	// Dictionary attack
	private static final int REQ_PICK_DIC = 0xD1C;
	private java.util.List<byte[]> dictKeys;

	// Armed action: runs now if a card is present, otherwise fires on next tag
	private volatile Runnable pendingTagAction;
	
	protected AlertDialog alertDialog;
	
	protected FileSaveFragment.Callbacks callbacks;

	protected BroadcastReceiver nfcStateChangeBroadcastReceiver;

	private TagPresenceScanner tagPresenceScanner;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		
		getFragmentManager().addOnBackStackChangedListener(this);
		
    	// Check for available NFC Adapter
    	PackageManager pm = getPackageManager();
    	if(pm.hasSystemFeature(PackageManager.FEATURE_NFC) && NfcAdapter.getDefaultAdapter(this) != null) {
        	Log.d(TAG, "NFC feature found");

    		nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        	if(!nfcAdapter.isEnabled()) {
        		startNfcSettingsActivity();
        		
        		showToast(R.string.nfcNotEnabledMessage);
        	}
        	
    		showMainFragment();
    		
    		tagPresenceScanner = new TagPresenceScanner(this);
    	} else {
        	Log.d(TAG, "NFC feature not found");

    		showToast(R.string.nfcNotAvailableMessage);
    		
    		finish();
    	}

	}

	@Override
	public void onResume() {
		super.onResume();
		
		nfcAdapter.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
	}

	@Override
	public void onPause() {
		super.onPause();
		
		nfcAdapter.disableReaderMode(this);
		
		tagPresenceScanner.pause();
	}

	@Override
	public void onTagDiscovered(Tag nfc) {
		IsoDep isoDep = IsoDep.get(nfc);
		
		FragmentManager fragmentManager = getFragmentManager();
		fragmentManager.popBackStack("main", 0);
		
		DefaultIsoDepWrapper isoDepWrapper = new DefaultIsoDepWrapper(isoDep);
		
		defaultIsoDepAdapter = new DefaultIsoDepAdapter(isoDepWrapper, false);
		
		try {
			isoDep.connect();
		
			setBackgroundColor(R.color.greenWhite);

			tag = mifare_desfire_tag_new();
			tag.setActive(1);
			tag.setIo(defaultIsoDepAdapter);

			// Fire any armed action now that the tag is connected, then stop (skip enumeration).
			Runnable pending = pendingTagAction;
			if (pending != null) {
				pendingTagAction = null;
				try {
					pending.run();
				} catch (Exception e) {
					Log.d(TAG, "pending action failed", e);
				}
				return;
			}

			desfireTag = new DesfireTag();
			
			VersionInfo versionInfo = mifare_desfire_get_version(tag);
			
			List<DesfireApplicationId> aids = mifare_desfire_get_application_ids(tag);
			if(aids != null) {
				Log.d(TAG, "Found applications " + aids.size());
				
				aids.add(0, new DesfireApplicationId()); // add default
				
				// 			DesfireApplicationKeySettings desfireApplicationKeySettings = mifare_desfire_get_key_settings(tag);
				applications = new ArrayList<DesfireApplication>();

				for(DesfireApplicationId aid : aids) {
					DesfireApplication desfireApplication = new DesfireApplication();
					desfireApplication.setId(aid.getId());
					
					applications.add(desfireApplication);
					
					Log.d(TAG, "Found application " + aid);
					
					if(mifare_desfire_select_application(tag, aid) == 0) {
						Log.d(TAG, "Selected application " + aid.toString());
						
						desfireApplication.setKeySettings(mifare_desfire_get_key_settings(tag));

						DesfireApplicationKeySettings keySettings = desfireApplication.getKeySettings();
					
						Log.d(TAG, keySettings.toString());
					}
				}
				
				desfireTag.setApplications(applications);
				
				showApplicationFragment(applications);

				tagPresenceScanner.resumeDelayed();
			} else {
				Log.d(TAG, "Did not find any applications");
			}
		} catch(Exception e) {
			Log.d(TAG, "Problem running commands", e);
		} finally {
			
		}
	}

	@Override
	public void onBackPressed() {
		FragmentManager fragmentManager = getFragmentManager();

		int count = fragmentManager.getBackStackEntryCount();
		Log.d(TAG, "onBackPressed " + count);
	    if (count == 1) {
	        this.finish();
	    } else {
	    	if(count == 2) {
    			setBackgroundColor(R.color.white);
	    	}
	    	fragmentManager.popBackStack();
	    }
	    
	    
	}
	
	private void setBackgroundColor(final int color) {
		MainActivity.this.runOnUiThread(new Runnable() {
		    public void run() {
				View view = findViewById(R.id.rootLayout);
				view.setBackgroundColor(getResources().getColor(color));
		    }
		});		
	}

	private void showApplicationFragment(final List<DesfireApplication> applications) {
		Log.d(TAG, "showApplicationFragment");
		
		FragmentManager fragmentManager = getFragmentManager();
		
		// Create new fragment and transaction
		ApplicationListFragment newFragment = new ApplicationListFragment();
		newFragment.setApplications(applications);
		newFragment.setOnItemClickListener(new OnItemClickListener(){

			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
				Log.d(TAG, "onItemClick "  + position + " for " + id);
				
				int parentId = parent.getId();
				
				if(parentId == R.id.listView) {
					application = applications.get(position);
					
					Log.d(TAG, "Click on application " + application.getIdString());
					
					MainActivity.this.authenticatedKey = null;

					try {
						if(tag.getSelectedApplication() != application.getIdInt()) {
							
							if(!isConnected()) {
								Log.d(TAG, "Tag lost wanting to change application");

								onTagLost();

								return;
							}
							
							try {
								if(mifare_desfire_select_application(tag, new DesfireApplicationId(application.getId())) != 0) {
									Log.d(TAG, "Unable to select application");
								}
							} catch (Exception e) {
								Log.d(TAG, "Problem selecting app " + application.getIdString(), e);
								
								return;
							}
						}

						if(!application.hasKeys()) {
							if(!isConnected()) {
								Log.d(TAG, "Tag lost wanting to get keys");
								
								onTagLost();
								
								return;
							}
							
							Log.d(TAG, "Get application keys");
							DesfireKeyType type = application.getKeySettings().getType();
							for(int i = 0; i < application.getKeySettings().getMaxKeys(); i++) {
								
								try {
									byte version = mifare_desfire_get_key_version(tag, (byte)i);
									
									application.add(new DesfireApplicationKey(i, DesfireKey.newInstance(type, version)));
								} catch(IllegalArgumentException e) {
									// assume no key set
								}
							}
						} else {
							Log.d(TAG, "Already read key versions");
						}
						
						if(application.getIdInt() != 0) {
							
							if(!application.hasFiles()) {
								if(!isConnected()) {
									Log.d(TAG, "Tag lost wanting to read application files");
									
									onTagLost();
									
									return;
								}
								
								readApplicationFiles();
							} else {
								Log.d(TAG, "Already read file settings");
							}

						}
						
						showApplicationFragment();
						
					} catch (Exception e) {
						Log.d(TAG, "Problem selecting app " + application.getIdString(), e);
					}
				}
				
			}

			private boolean readApplicationFiles() throws Exception {
				Log.d(TAG, "Get application files");

				DesfireApplicationKeySettings keySettings = application.getKeySettings();
				
				Log.d(TAG, keySettings.toString());
				
				if(keySettings.isRequiresMasterKeyForDirectoryList()) {
					final List<DesfireApplicationKey> keys = application.getKeys();
					
					final DesfireApplicationKey root = keys.get(0);
					
					showKeySelector(keySettings.getType(), new OnKeyListener() {
						
						@Override
						public void onKey(DesfireKey key) {
							if(!isConnected()) {
								Log.d(TAG, "Tag lost wanting to select application");

								onTagLost();

								return;
							}

							try {
								DesfireApplicationKey clone = new DesfireApplicationKey(root.getIndex(), key);

								if(authenticate(clone)) {
									MainActivity.this.authenticatedKey = clone;

									readApplicationFiles();
									
									showApplicationFragment();

									showToast(R.string.applicationAuthenticatedSuccess);
								} else {
									showToast(R.string.applicationAuthenticatedFail);
								}

							} catch (Exception e) {
								Log.d(TAG, "Unable to authenticate", e);
								
								showToast(R.string.applicationAuthenticatedFail);
							}
							
						}
					});

				} else {
					Log.d(TAG, "Can list files");
				}					
				
				Log.d(TAG, "Get files ids");
				byte[] ids = mifare_desfire_get_file_ids(tag);
				
				if(ids != null) {
					Log.d(TAG, "Got " + ids.length + " files");
					
					for(int i = 0; i < ids.length; i++) {
						DesfireFile settings = mifare_desfire_get_file_settings(tag, ids[i]);
						
					    Log.d(TAG, "File setting " + i + ": " + settings);

						application.add(settings);
					}
				} else {
					Log.d(TAG, "Unable to get files ids");
				}
				
				return true;
			}
			
		});
		
		FragmentTransaction transaction = fragmentManager.beginTransaction();

		// Replace whatever is in the fragment_container view with this fragment,
		// and add the transaction to the back stack
		transaction.replace(R.id.content, newFragment, "applications");
		transaction.addToBackStack("applications");

		// Commit the transaction
		transaction.commit();
	}

	protected void onTagLost() {
		showShortToast(R.string.tagStatusLost);
		
		setBackgroundColor(R.color.redWhite);
	}

	// ----- Script runner (raw APDU) -----

	private void showScriptRunner() {
		final android.widget.EditText input = new android.widget.EditText(this);
		input.setHint("Une APDU par ligne, ex:\n90 6A 00 00 00");
		input.setGravity(android.view.Gravity.TOP | android.view.Gravity.START);
		input.setMinLines(5);
		input.setTypeface(android.graphics.Typeface.MONOSPACE);
		input.setInputType(android.text.InputType.TYPE_CLASS_TEXT
				| android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
				| android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);

		AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setTitle("Run Script");
		builder.setView(input);
		builder.setPositiveButton("Run", null);
		builder.setNegativeButton("Cancel", null);
		final AlertDialog dialog = builder.create();
		dialog.show();
		dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				final String script = input.getText().toString();
				dialog.dismiss();
				armOrRun(new Runnable() {
					@Override
					public void run() {
						runScript(script);
					}
				});
			}
		});
	}

	private void runScript(final String script) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				final StringBuilder sb = new StringBuilder();
				try {
					DefaultIsoDepWrapper wrapper = (DefaultIsoDepWrapper) tag.getIo().getIsoDepWrapper();
					// nfcjlib high-level session (crypto auth etc.), bound to the live adapter
					com.github.skjolber.desfire.nfcjlib.core.DESFireEV1 desfire =
							new com.github.skjolber.desfire.nfcjlib.core.DESFireEV1();
					desfire.setAdapter(defaultIsoDepAdapter);

					String[] lines = script.split("\n");
					byte[] lastAid = null; // remembered for auto re-select before each AUTH (dictionary mode)
					for (String rawLine : lines) {
						String line = rawLine;
						// strip comments (# or // , full line or inline)
						int hash = line.indexOf('#');
						if (hash >= 0) {
							line = line.substring(0, hash);
						}
						int dslash = line.indexOf("//");
						if (dslash >= 0) {
							line = line.substring(0, dslash);
						}
						String trimmed = line.trim();
						if (trimmed.length() == 0) {
							continue;
						}
						String upper = trimmed.toUpperCase();

						// ----- High-level nfcjlib commands -----
						if (upper.startsWith("SELECT")) {
							try {
								String aidHex = trimmed.substring(6).replaceAll("\\s", "");
								byte[] aid = hexToBytes(aidHex);
								boolean ok = desfire.selectApplication(aid);
								if (ok) {
									lastAid = aid;
								}
								sb.append(">> SELECT ").append(aidHex).append("\n");
								sb.append("<< ").append(ok ? "OK" : "ECHEC (AID introuvable ?)").append("\n\n");
							} catch (Exception e) {
								sb.append(">> ").append(trimmed).append("\n<< ERREUR: ").append(e.getMessage())
										.append(" (format: SELECT <aid 3 octets, LSB first>)\n\n");
							}
							continue;
						}
						if (upper.startsWith("AUTH")) {
							try {
								String[] t = trimmed.split("\\s+");
								int keyNo = Integer.decode(t[1]);
								String keyHex = t[2].replaceAll("[^0-9A-Fa-f]", "");
								byte[] key = hexToBytes(keyHex);
								// auto re-select before each attempt so a prior failed AUTH
								// doesn't poison the next one (practical dictionary mode)
								if (lastAid != null) {
									desfire.selectApplication(lastAid);
								}
								boolean ok = desfire.authenticate(key, (byte) keyNo,
										com.github.skjolber.desfire.ev1.model.key.DesfireKeyType.AES);
								sb.append(">> AUTH key").append(keyNo).append(" AES ").append(keyHex).append("\n");
								sb.append("<< ").append(ok ? "AUTH SUCCESS" : "AUTH FAIL").append("\n\n");
							} catch (Exception e) {
								sb.append(">> ").append(trimmed).append("\n<< ERREUR: ").append(e.getMessage())
										.append(" (format: AUTH <keyno> <32 hex>)\n\n");
							}
							continue;
						}
						if (upper.startsWith("READ")) {
							try {
								String[] t = trimmed.split("\\s+");
								int fileNo = Integer.decode(t[1]);
								int offset = Integer.decode(t[2]);
								int length = Integer.decode(t[3]);
								byte[] data = desfire.readData((byte) fileNo, offset, length);
								sb.append(">> READ file").append(fileNo).append(" off").append(offset)
										.append(" len").append(length).append("\n");
								if (data != null) {
									sb.append("<< ").append(Utils.getHexString(data, true)).append("\n");
									sb.append("   ascii: ").append(toAscii(data)).append("\n\n");
								} else {
									sb.append("<< (null / refuse - authentifie-toi avec la bonne cle d'abord)\n\n");
								}
							} catch (Exception e) {
								sb.append(">> ").append(trimmed).append("\n<< ERREUR: ").append(e.getMessage())
										.append(" (format: READ <fileno> <offset> <length>)\n\n");
							}
							continue;
						}

						if (upper.startsWith("CHFILESETTINGS")) {
							try {
								String[] t = trimmed.split("\\s+");
								int fileNo = Integer.decode(t[1]);
								int comm = Integer.parseInt(t[2], 16);
								int ar1 = Integer.parseInt(t[3], 16);
								int ar2 = Integer.parseInt(t[4], 16);
								boolean ok = desfire.changeFileSettings((byte) fileNo, (byte) comm,
										(byte) ar1, (byte) ar2);
								sb.append(">> CHFILESETTINGS file").append(fileNo)
										.append(" comm=").append(t[2]).append(" ar=").append(t[3]).append(t[4]).append("\n");
								sb.append("<< ").append(ok ? "OK" : "ECHEC (authentifie-toi avec la cle Change d'abord)").append("\n\n");
							} catch (Exception e) {
								sb.append(">> ").append(trimmed).append("\n<< ERREUR: ").append(e.getMessage())
										.append(" (format: CHFILESETTINGS <fileno> <comm> <ar1> <ar2>, en hex)\n\n");
							}
							continue;
						}

						// ----- Raw APDU -----
						String clean = trimmed.replaceAll("\\s", "");
						if (!clean.matches("[0-9A-Fa-f]+")) {
							sb.append(">> ").append(trimmed).append("\n");
							sb.append("<< ERREUR: caracteres non-hex (commentaire ? prefixe la ligne par #)\n\n");
							continue;
						}
						if (clean.length() % 2 != 0) {
							sb.append(">> ").append(trimmed).append("\n");
							sb.append("<< ERREUR: nombre impair de caracteres hex\n\n");
							continue;
						}
						byte[] cmd = hexToBytes(clean);
						try {
							byte[] resp = wrapper.transceive(cmd);
							sb.append(">> ").append(Utils.getHexString(cmd, true)).append("\n");
							sb.append("<< ").append(Utils.getHexString(resp, true)).append("\n\n");
						} catch (Exception e) {
							sb.append(">> ").append(Utils.getHexString(cmd, true)).append("\n");
							sb.append("<< ERREUR: ").append(e.getMessage()).append("\n\n");
						}
					}
				} catch (Exception e) {
					sb.append("ERREUR: ").append(e.getMessage()).append("\n");
				}
				runOnUiThread(new Runnable() {
					@Override
					public void run() {
						showScriptResult(sb.toString());
					}
				});
			}
		}).start();
	}

	private void showScriptResult(String result) {
		final android.widget.TextView tv = new android.widget.TextView(this);
		tv.setText(result.length() == 0 ? "(aucune sortie)" : result);
		tv.setTypeface(android.graphics.Typeface.MONOSPACE);
		tv.setTextIsSelectable(true);
		tv.setPadding(32, 24, 32, 24);
		final android.widget.ScrollView scroll = new android.widget.ScrollView(this);
		scroll.addView(tv);

		AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setTitle("Resultat");
		builder.setView(scroll);
		builder.setPositiveButton("OK", null);
		builder.setNeutralButton("Copier", new android.content.DialogInterface.OnClickListener() {
			@Override
			public void onClick(android.content.DialogInterface d, int w) {
				android.content.ClipboardManager cm =
						(android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
				cm.setPrimaryClip(android.content.ClipData.newPlainText("script result", tv.getText()));
				Toast.makeText(MainActivity.this, "Copie", Toast.LENGTH_SHORT).show();
			}
		});
		builder.show();
	}

	private static byte[] hexToBytes(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	private static String toAscii(byte[] data) {
		StringBuilder s = new StringBuilder();
		for (byte b : data) {
			int c = b & 0xFF;
			s.append((c >= 32 && c < 127) ? (char) c : '.');
		}
		return s.toString();
	}

	// Run op now if a card is already present, otherwise arm it to fire when one is tapped.
	private void armOrRun(final Runnable op) {
		if (isConnected()) {
			op.run();
		} else {
			pendingTagAction = op;
			Toast.makeText(this, "Pose la carte sur le telephone pour lancer...", Toast.LENGTH_LONG).show();
		}
	}

	// ----- Dictionary attack -----

	private void pickDictionaryFile() {
		Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
		intent.addCategory(Intent.CATEGORY_OPENABLE);
		intent.setType("*/*");
		try {
			startActivityForResult(intent, REQ_PICK_DIC);
		} catch (Exception e) {
			Toast.makeText(this, "Aucun gestionnaire de fichiers", Toast.LENGTH_SHORT).show();
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
		if (requestCode == REQ_PICK_DIC && resultCode == RESULT_OK
				&& data != null && data.getData() != null) {
			loadDictionary(data.getData());
		}
	}

	private void loadDictionary(android.net.Uri uri) {
		java.util.List<byte[]> keys = new java.util.ArrayList<byte[]>();
		int skipped = 0;
		try {
			java.io.BufferedReader br = new java.io.BufferedReader(
					new java.io.InputStreamReader(getContentResolver().openInputStream(uri)));
			String line;
			while ((line = br.readLine()) != null) {
				int h = line.indexOf('#');
				if (h >= 0) {
					line = line.substring(0, h);
				}
				String clean = line.replaceAll("[^0-9A-Fa-f]", "");
				if (clean.length() == 0) {
					continue;
				}
				if (clean.length() == 32) {
					keys.add(hexToBytes(clean));
				} else {
					skipped++;
				}
			}
			br.close();
		} catch (Exception e) {
			Toast.makeText(this, "Erreur lecture: " + e.getMessage(), Toast.LENGTH_LONG).show();
			return;
		}
		dictKeys = keys;
		showDictRunDialog(keys.size(), skipped);
	}

	private void showDictRunDialog(final int count, int skipped) {
		android.widget.LinearLayout layout = new android.widget.LinearLayout(this);
		layout.setOrientation(android.widget.LinearLayout.VERTICAL);
		layout.setPadding(40, 20, 40, 0);
		android.widget.TextView info = new android.widget.TextView(this);
		info.setText(count + " cles AES chargees"
				+ (skipped > 0 ? " (" + skipped + " lignes ignorees)" : "")
				+ "\nPose la carte, puis Lancer.");
		final android.widget.EditText aidInput = new android.widget.EditText(this);
		aidInput.setHint("AID (ex: 010000)");
		aidInput.setText("010000");
		final android.widget.EditText keyInput = new android.widget.EditText(this);
		keyInput.setHint("Key number (ex: 1)");
		keyInput.setText("1");
		layout.addView(info);
		layout.addView(aidInput);
		layout.addView(keyInput);

		AlertDialog.Builder b = new AlertDialog.Builder(this);
		b.setTitle("Dictionnaire AES");
		b.setView(layout);
		b.setPositiveButton("Lancer", null);
		b.setNegativeButton("Annuler", null);
		final AlertDialog dialog = b.create();
		dialog.show();
		dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				if (count == 0) {
					Toast.makeText(MainActivity.this, "Aucune cle valide dans le fichier", Toast.LENGTH_SHORT).show();
					return;
				}
				byte[] aid;
				int keyNo;
				try {
					aid = hexToBytes(aidInput.getText().toString().replaceAll("\\s", ""));
					keyNo = Integer.decode(keyInput.getText().toString().trim());
				} catch (Exception e) {
					Toast.makeText(MainActivity.this, "AID ou key number invalide", Toast.LENGTH_SHORT).show();
					return;
				}
				dialog.dismiss();
				armOrRun(new Runnable() {
					@Override
					public void run() {
						runDictAttack(aid, (byte) keyNo);
					}
				});
			}
		});
	}

	private void runDictAttack(final byte[] aid, final byte keyNo) {
		final java.util.List<byte[]> keys = dictKeys;
		final int ksize = keys.size();
		runOnUiThread(new Runnable() {
			@Override
			public void run() {
				Toast.makeText(MainActivity.this, "Test de " + ksize + " cles...", Toast.LENGTH_SHORT).show();
			}
		});
		new Thread(new Runnable() {
			@Override
			public void run() {
				final StringBuilder sb = new StringBuilder();
				byte[] found = null;
				int tried = 0;
				try {
					com.github.skjolber.desfire.nfcjlib.core.DESFireEV1 desfire =
							new com.github.skjolber.desfire.nfcjlib.core.DESFireEV1();
					desfire.setAdapter(defaultIsoDepAdapter);
					for (byte[] key : keys) {
						tried++;
						try {
							desfire.selectApplication(aid);
							if (desfire.authenticate(key, keyNo,
									com.github.skjolber.desfire.ev1.model.key.DesfireKeyType.AES)) {
								found = key;
								break;
							}
						} catch (Exception e) {
							if (!isConnected()) {
								sb.append("Carte perdue apres ").append(tried).append(" essais.\n");
								break;
							}
						}
					}
				} catch (Exception e) {
					sb.append("ERREUR: ").append(e.getMessage()).append("\n");
				}
				final byte[] foundF = found;
				final int triedF = tried;
				runOnUiThread(new Runnable() {
					@Override
					public void run() {
						if (foundF != null) {
							sb.append("=== CLE TROUVEE (key").append(keyNo).append(") ===\n");
							sb.append(Utils.getHexString(foundF, true)).append("\n");
							sb.append("(apres ").append(triedF).append(" essais)\n");
						} else {
							sb.append("Aucune des ").append(keys.size())
									.append(" cles n'a fonctionne sur key").append(keyNo).append(".\n");
						}
						showScriptResult(sb.toString());
					}
				});
			}
		}).start();
	}

	// ----- Dump + Restore (read a protected file via the Change key, then put settings back) -----

	private void showDumpRestoreDialog() {
		android.widget.LinearLayout layout = new android.widget.LinearLayout(this);
		layout.setOrientation(android.widget.LinearLayout.VERTICAL);
		layout.setPadding(40, 20, 40, 0);
		final android.widget.EditText aidInput = new android.widget.EditText(this);
		aidInput.setHint("AID (ex: 010000)");
		aidInput.setText("010000");
		final android.widget.EditText fileInput = new android.widget.EditText(this);
		fileInput.setHint("File number (ex: 1)");
		fileInput.setText("1");
		final android.widget.EditText keyNoInput = new android.widget.EditText(this);
		keyNoInput.setHint("Change key number (ex: 0)");
		keyNoInput.setText("0");
		final android.widget.EditText keyInput = new android.widget.EditText(this);
		keyInput.setHint("Change key (32 hex)");
		keyInput.setText("00000000000000000000000000000000");
		layout.addView(aidInput);
		layout.addView(fileInput);
		layout.addView(keyNoInput);
		layout.addView(keyInput);

		AlertDialog.Builder b = new AlertDialog.Builder(this);
		b.setTitle("Dump + Restore");
		b.setView(layout);
		b.setPositiveButton("Lancer", null);
		b.setNegativeButton("Annuler", null);
		final AlertDialog dialog = b.create();
		dialog.show();
		dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
			@Override
			public void onClick(View v) {
				byte[] aid;
				int fileNo;
				int keyNo;
				byte[] key;
				try {
					aid = hexToBytes(aidInput.getText().toString().replaceAll("\\s", ""));
					fileNo = Integer.decode(fileInput.getText().toString().trim());
					keyNo = Integer.decode(keyNoInput.getText().toString().trim());
					key = hexToBytes(keyInput.getText().toString().replaceAll("[^0-9A-Fa-f]", ""));
				} catch (Exception e) {
					Toast.makeText(MainActivity.this, "Parametres invalides", Toast.LENGTH_SHORT).show();
					return;
				}
				dialog.dismiss();
				armOrRun(new Runnable() {
					@Override
					public void run() {
						runDumpRestore(aid, fileNo, (byte) keyNo, key);
					}
				});
			}
		});
	}

	private void runDumpRestore(final byte[] aid, final int fileNo, final byte changeKeyNo, final byte[] changeKey) {
		runOnUiThread(new Runnable() {
			@Override
			public void run() {
				Toast.makeText(MainActivity.this, "Dump + Restore en cours...", Toast.LENGTH_SHORT).show();
			}
		});
		new Thread(new Runnable() {
			@Override
			public void run() {
				final StringBuilder sb = new StringBuilder();
				boolean opened = false;
				byte origComm = 0, origAr1 = 0, origAr2 = 0;
				try {
					DefaultIsoDepWrapper w = (DefaultIsoDepWrapper) tag.getIo().getIsoDepWrapper();
					com.github.skjolber.desfire.nfcjlib.core.DESFireEV1 desfire =
							new com.github.skjolber.desfire.nfcjlib.core.DESFireEV1();
					desfire.setAdapter(defaultIsoDepAdapter);

					byte[] sel = new byte[]{(byte) 0x90, 0x5A, 0, 0, 0x03, aid[0], aid[1], aid[2], 0};
					w.transceive(sel);
					byte[] gfs = w.transceive(new byte[]{(byte) 0x90, (byte) 0xF5, 0, 0, 0x01, (byte) fileNo, 0});

					if (gfs.length < 9 || (gfs[gfs.length - 2] & 0xFF) != 0x91 || (gfs[gfs.length - 1] & 0xFF) != 0x00) {
						sb.append("GetFileSettings a echoue (").append(Utils.getHexString(gfs, true)).append("). Abandon, carte intacte.\n");
					} else {
						origComm = gfs[1];
						origAr1 = gfs[2];
						origAr2 = gfs[3];
						int size = (gfs[4] & 0xFF) | ((gfs[5] & 0xFF) << 8) | ((gfs[6] & 0xFF) << 16);
						sb.append("Config d'origine: comm=").append(String.format("%02X", origComm & 0xFF))
								.append(" ar=").append(String.format("%02X%02X", origAr1 & 0xFF, origAr2 & 0xFF))
								.append(" taille=").append(size).append(" octets\n\n");

						desfire.selectApplication(aid);
						if (!desfire.authenticate(changeKey, changeKeyNo,
								com.github.skjolber.desfire.ev1.model.key.DesfireKeyType.AES)) {
							sb.append("AUTH cle Change (key").append(changeKeyNo & 0xFF)
									.append(") echouee. Abandon, carte intacte.\n");
						} else {
							byte newAr1 = origAr1;
							byte newAr2 = (byte) (0xE0 | (origAr2 & 0x0F)); // Read = libre
							if (!desfire.changeFileSettings((byte) fileNo, (byte) 0x00, newAr1, newAr2)) {
								sb.append("Ouverture (ChangeFileSettings) echouee. Carte intacte.\n");
							} else {
								opened = true;
								w.transceive(sel); // fresh select, lecture libre maintenant
								byte[] rd = new byte[]{(byte) 0x90, (byte) 0xBD, 0, 0, 0x07, (byte) fileNo, 0, 0, 0,
										(byte) (size & 0xFF), (byte) ((size >> 8) & 0xFF), (byte) ((size >> 16) & 0xFF), 0};
								byte[] content = w.transceive(rd);
								if (content.length >= 2 && (content[content.length - 2] & 0xFF) == 0x91
										&& (content[content.length - 1] & 0xFF) == 0x00) {
									byte[] payload = java.util.Arrays.copyOf(content, content.length - 2);
									sb.append(">>> CONTENU: ").append(Utils.getHexString(payload, true)).append("\n");
									sb.append("    ascii: ").append(toAscii(payload)).append("\n\n");
								} else {
									sb.append("Lecture: reponse inattendue ").append(Utils.getHexString(content, true)).append("\n\n");
								}
							}
						}
					}
				} catch (Exception e) {
					sb.append("ERREUR phase dump: ").append(e.getMessage()).append("\n");
				}

				// ---- RESTORE (seulement si on a ouvert) ----
				if (opened) {
					try {
						DefaultIsoDepWrapper w2 = (DefaultIsoDepWrapper) tag.getIo().getIsoDepWrapper();
						com.github.skjolber.desfire.nfcjlib.core.DESFireEV1 d2 =
								new com.github.skjolber.desfire.nfcjlib.core.DESFireEV1();
						d2.setAdapter(defaultIsoDepAdapter);
						d2.selectApplication(aid);
						boolean ra = d2.authenticate(changeKey, changeKeyNo,
								com.github.skjolber.desfire.ev1.model.key.DesfireKeyType.AES);
						boolean rs = ra && d2.changeFileSettings((byte) fileNo, origComm, origAr1, origAr2);
						w2.transceive(new byte[]{(byte) 0x90, 0x5A, 0, 0, 0x03, aid[0], aid[1], aid[2], 0});
						byte[] chk = w2.transceive(new byte[]{(byte) 0x90, (byte) 0xF5, 0, 0, 0x01, (byte) fileNo, 0});
						boolean ok = chk.length >= 4 && chk[1] == origComm && chk[2] == origAr1 && chk[3] == origAr2;
						if (rs && ok) {
							sb.append("RESTAURATION OK — carte identique a l'origine (verifie).\n");
						} else {
							sb.append("!!! RESTAURATION INCOMPLETE (auth=").append(ra).append(" chg=").append(rs)
									.append(" verif=").append(ok).append("). Fichier peut-etre laisse OUVERT.\n");
						}
					} catch (Exception e) {
						sb.append("!!! ERREUR RESTAURATION: ").append(e.getMessage())
								.append(" — fichier peut-etre laisse OUVERT, restaure a la main !\n");
					}
				}

				runOnUiThread(new Runnable() {
					@Override
					public void run() {
						showScriptResult(sb.toString());
					}
				});
			}
		}).start();
	}

	private void showMainFragment() {
		Log.d(TAG, "showMainFragment");

		// Create new fragment and transaction
		final MainFragment newFragment = new MainFragment();
		
		FragmentTransaction transaction = getFragmentManager().beginTransaction();

		// Replace whatever is in the fragment_container view with this fragment,
		// and add the transaction to the back stack
		transaction.replace(R.id.content, newFragment, "main");
		transaction.addToBackStack("main");

		// Commit the transaction
		transaction.commit();
	}

	

	private void showApplicationFragment() {
		Log.d(TAG, "showApplicationFragment");
		
		// Create new fragment and transaction
		final FileListFragment newFragment = new FileListFragment();
		newFragment.setApplication(application);
		newFragment.setOnItemClickListener(new OnItemClickListener(){

			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
				Log.d(TAG, "onItemClick "  + position + " for " + id);
				
				ApplicationDetail applicationDetail = newFragment.getApplicationDetail(position);
				
				if(applicationDetail instanceof ApplicationDetailFile) {
					ApplicationDetailFile file = (ApplicationDetailFile)applicationDetail;
					
					final DesfireFile desfireFile = file.getFile();
					
					Log.d(TAG, "Select file " + desfireFile);

					if(desfireFile.isContent()) {
						Log.d(TAG, "Already read file content");

						showFileFragment(desfireFile);
						
						return;
					}

					if(!isConnected()) {
						onTagLost();
						
						return;
					}
					
					if(!desfireFile.isFreeReadWriteAccess()) {
						if(authenticatedKey != null) {
							Log.d(TAG, "Already authenticated using key " + authenticatedKey.getIndex());
						
							if(desfireFile.freeReadAccess() || desfireFile.isReadAccess(authenticatedKey.getIndex())) {
								Log.d(TAG, "Already authenticated with read file access");
								
								if(!desfireFile.freeReadAccess()) {
									try {
										if(authenticate(authenticatedKey)) {
											readFile(desfireFile);
										}
									} catch (Exception e) {
										Log.d(TAG, "Unable to authenticate", e);
										
										showToast(R.string.applicationAuthenticatedFail);
									}
								} else {
									readFile(desfireFile);
								}
								
								showFileFragment(desfireFile);
								
								return;
							}
						}
							
							
						showKeyNumber(desfireFile, new OnKeyNumberListener() {
							
							@Override
							public void onKeyNumber(int index, final String access) {
								
								if(!isConnected()) {
									onTagLost();
									
									return;
								}
								
								final DesfireApplicationKey desfire = application.getKeys().get(index);
								
								showKeySelector(application.getKeySettings().getType(), new OnKeyListener() {
									
									@Override
									public void onKey(DesfireKey key) {
										try {
											DesfireApplicationKey clone = new DesfireApplicationKey(desfire.getIndex(), key);
											
											if(authenticate(clone)) {
												MainActivity.this.authenticatedKey = clone;

												if(desfireFile.freeReadAccess() || access.contains("R")) {
													readFile(desfireFile);
												}
												
												showFileFragment(desfireFile);

												showToast(R.string.applicationAuthenticatedSuccess);
											} else {
												showToast(R.string.applicationAuthenticatedFail);
											}
											
										} catch (Exception e) {
											Log.d(TAG, "Unable to authenticate", e);
											
											showToast(R.string.applicationAuthenticatedFail);
										}
										
									}
								});
								
							}
						});
							
						
					} else {
						try {
							readFile(desfireFile);

							showFileFragment(desfireFile);
						} catch (Exception e) {
							Log.d(TAG, "Problem reading file", e);
						}

					}
					
				} else if(applicationDetail instanceof ApplicationDetailApplicationKey) {
					ApplicationDetailApplicationKey key = (ApplicationDetailApplicationKey)applicationDetail;
					
					final DesfireApplicationKey desfire = key.getKey();
					
					Log.d(TAG, "Select key " + desfire);
					
					DesfireKey desfireKey = desfire.getDesfireKey();
					
					DesfireKeyType type = desfireKey.getType();
					
					showKeySelector(type, new OnKeyListener() {
						
						@Override
						public void onKey(DesfireKey key) {
							if(!isConnected()) {
								Log.d(TAG, "Tag lost wanting to change application");

								onTagLost();

								return;
							}

							try {
								DesfireApplicationKey clone = new DesfireApplicationKey(desfire.getIndex(), key);
								
								if(authenticate(clone)) {
									MainActivity.this.authenticatedKey = clone;
									
									showToast(R.string.applicationAuthenticatedSuccess);
								} else {
									showToast(R.string.applicationAuthenticatedFail);
								}
							} catch (Exception e) {
								Log.d(TAG, "Unable to authenticate", e);
								
								showToast(R.string.applicationAuthenticatedFail);
							}
							
						}
					});
				}
				
			}

		});
		
		FragmentTransaction transaction = getFragmentManager().beginTransaction();

		// Replace whatever is in the fragment_container view with this fragment,
		// and add the transaction to the back stack
		transaction.replace(R.id.content, newFragment, "application");
		transaction.addToBackStack("application");

		// Commit the transaction
		transaction.commit();		
	}

	private String getName(DesfireKeyType type) {
		switch(type) {
			case TDES : return getString(R.string.applicationAuthenticateKey3DES);
			case TKTDES: return getString(R.string.applicationAuthenticateKey3K3DES);
			case AES : return getString(R.string.applicationAuthenticateKeyAES);
			case DES : return getString(R.string.applicationAuthenticateKeyDES);
		default:
			throw new IllegalArgumentException();
		}
	}
	

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
	    MenuInflater inflater = getMenuInflater();
	    inflater.inflate(R.menu.main, menu);
	    
	    return true;
	}
	
	@Override
	public boolean onPrepareOptionsMenu(Menu menu) {
		for(int i = 0; i < menu.size(); i++) {
			menu.getItem(i).setVisible(false);
		}

		// Script runner + dictionary: always available
		MenuItem script = menu.findItem(R.id.action_script);
		if(script != null) {
			script.setVisible(true);
		}
		MenuItem dict = menu.findItem(R.id.action_dict);
		if(dict != null) {
			dict.setVisible(true);
		}
		MenuItem dump = menu.findItem(R.id.action_dump);
		if(dump != null) {
			dump.setVisible(true);
		}

		MenuItem keys = menu.findItem(R.id.action_settings);
		MenuItem addKey = menu.findItem(R.id.action_add);
		MenuItem save = menu.findItem(R.id.action_save);

		FragmentManager fragmentManager = getFragmentManager();
		
		String name = fragmentManager.getBackStackEntryAt(fragmentManager.getBackStackEntryCount() - 1).getName();
		if(name != null && name.equals("keys")) {
			keys.setVisible(false);
			addKey.setVisible(true);
		} else {
			keys.setVisible(true);
			addKey.setVisible(false);
		}
		
		Log.d(TAG, "Prepare options menu for " + name);
		if(name != null && name.equals("file")) {
			getFragmentManager().executePendingTransactions();
			
			FileFragment fragment = (FileFragment) fragmentManager.findFragmentByTag("file");
			
			DesfireFile file = fragment.getFile();

			if(file instanceof ValueDesfireFile) {
				save.setVisible(false);
			} else {
				save.setVisible(file.isContent());
			}
		} else {
			save.setVisible(false);
		}
		
		return super.onPrepareOptionsMenu(menu);
	}
	
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		if (item.getItemId() == R.id.action_settings) {
			showKeysFragment();
			return true;
		} else if (item.getItemId() == R.id.action_add) {
			addKey();
			return true;
		} else if (item.getItemId() == R.id.action_save) {
			saveFileData();
			return true;
		} else if (item.getItemId() == R.id.action_script) {
			showScriptRunner();
			return true;
		} else if (item.getItemId() == R.id.action_dict) {
			pickDictionaryFile();
			return true;
		} else if (item.getItemId() == R.id.action_dump) {
			showDumpRestoreDialog();
			return true;
		} else {
			return super.onOptionsItemSelected(item);
		}

		/*
		switch (item.getItemId()) {
    	case R.id.action_settings: {
    		showKeysFragment();
    		return true;
    	}
    	case R.id.action_add: {
    		addKey();
    		return true;
    	}
    	case R.id.action_save : {
    		saveFileData();
    		return true;
    	}
    	default:
    		return super.onOptionsItemSelected(item);
    	}
		*/
	}
	
	private void addKey() {
		KeyListFragment fragment = (KeyListFragment) getFragmentManager().findFragmentByTag("keys");
		
		fragment.showAddKey(null);

	}

	private void saveFileData() {
		  String fragTag = "saveFileData";

		  // Get an instance supplying a default extension, captions and
		  // icon appropriate to the calling application/activity.
		  FileSaveFragment fsf = FileSaveFragment.newInstance("bin", 
		                                                      R.string.fileSaveDialogOk, 
		                                                      R.string.fileSaveDialogCancel,
		                                                      R.string.fileSaveDialogSaveAs,
		                                                      R.string.fileSaveDialogHintFilenameUnadorned,
		                                                      android.R.drawable.ic_menu_save);
		  fsf.show(getFragmentManager(), fragTag);	
		  
		  this.callbacks = new FileCallbacks(); 
	}

	private void showKeysFragment() {
		Log.d(TAG, "showKeysFragment");
		
		// Create new fragment and transaction
		final KeyListFragment newFragment = new KeyListFragment();
		newFragment.setContext(this);
		
		newFragment.setOnItemClickListener(new OnItemClickListener(){

			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
				Log.d(TAG, "onItemClick "  + position + " for " + id);
				
				ApplicationDetail applicationDetail = newFragment.getApplicationDetail(position);
				
				if(applicationDetail instanceof ApplicationDetailKey) {
					ApplicationDetailKey key = (ApplicationDetailKey)applicationDetail;
					
					DesfireKey desfire = key.getKey();
					
					Log.d(TAG, "Show details for key " + desfire);
					
					KeyListFragment fragment = (KeyListFragment) getFragmentManager().findFragmentByTag("keys");
					
					fragment.showAddKey(desfire);

				}
				
			}
			
		});
		FragmentTransaction transaction = getFragmentManager().beginTransaction();

		// Replace whatever is in the fragment_container view with this fragment,
		// and add the transaction to the back stack
		transaction.replace(R.id.content, newFragment, "keys");
		transaction.addToBackStack("keys");

		// Commit the transaction
		transaction.commit();		
	}

	private boolean authenticate(DesfireApplicationKey desfireApplicationKey) throws Exception {
		
		DesfireKey key = desfireApplicationKey.getDesfireKey();

		Log.d(TAG, "Authenticate key " + (byte)desfireApplicationKey.getIndex());
		
	    /* Authenticate with this key */
	    switch (key.getType()) {
	    case AES : {

	    	DesfireAESKey aesKey = (DesfireAESKey)key;
	    	
	    	MifareDESFireKey mifareDESFireKey = MifareDesfireKey1.mifare_desfire_aes_key_new_with_version(aesKey.getValue(), (byte)key.getVersion());
	    	
			int result = mifare_desfire_authenticate_aes (tag, (byte)desfireApplicationKey.getIndex(), mifareDESFireKey);
			
			if(result == 0) {
				Log.d(TAG, "Authenticated AES using key " + key.getName() + " index " + (byte)desfireApplicationKey.getIndex());
				
				return true;
			} else {
				Log.d(TAG, "Unable to authenticate AES using key " + key.getName());
			}
			
	    	break;
	    }
	    case TKTDES : {

	    	Desfire3K3DESKey desfire3k3desKey = (Desfire3K3DESKey)key;

	    	MifareDESFireKey mifareDESFireKey = MifareDesfireKey1.mifare_desfire_3k3des_key_new(desfire3k3desKey.getValue());

			int result = mifare_desfire_authenticate_iso (tag, (byte)desfireApplicationKey.getIndex(), mifareDESFireKey);

			if(result == 0) {
				Log.d(TAG, "Authenticated 3K3DES using key " + key.getName());
				
				return true;
			} else {
				Log.d(TAG, "Unable to authenticate 3K3DES using key " + key.getName());
			}

	    	break;
	    }
	    case TDES : {

	    	Desfire3DESKey desfire3desKey = (Desfire3DESKey)key;

	    	MifareDESFireKey mifareDESFireKey = MifareDesfireKey1.mifare_desfire_3des_key_new(desfire3desKey.getValue());

	    	MifareDesfireKey1.mifare_desfire_key_set_version(mifareDESFireKey, (byte)desfire3desKey.getVersion());
	    	
			int result = mifare_desfire_authenticate (tag, (byte)desfireApplicationKey.getIndex(), mifareDESFireKey);

			if(result == 0) {
				Log.d(TAG, "Authenticated 3DES using key " + key.getName());
				
				return true;
			} else {
				Log.d(TAG, "Unable to authenticate 3DES using key " + key.getName());
			}

	    	break;
	    }
	    case DES : {

	    	DesfireDESKey desfireDesKey = (DesfireDESKey)key;

	    	MifareDESFireKey mifareDESFireKey = MifareDesfireKey1.mifare_desfire_des_key_new(desfireDesKey.getValue());

	    	MifareDesfireKey1.mifare_desfire_key_set_version(mifareDESFireKey, (byte)desfireDesKey.getVersion());
	    	
			int result = mifare_desfire_authenticate (tag, (byte)desfireApplicationKey.getIndex(), mifareDESFireKey);

			if(result == 0) {
				Log.d(TAG, "Authenticated DES using key " + key.getName());
				
				return true;
			} else {
				Log.d(TAG, "Unable to authenticate DES using key " + key.getName());
			}

	    	break;
	    }
	}
	    return false;
	}

	private void showKeyNumber(DesfireFile desfireFile, final OnKeyNumberListener listener) {
		
		final Map<Integer, String> compactPermissionMap = desfireFile.getCompactPermissionMap();
		
		final List<Integer> keyNumbers = new ArrayList<>(compactPermissionMap.keySet());
		Collections.sort(keyNumbers);
		
		List<String> keys = new ArrayList<>();
		
		for(int i = 0; i < keyNumbers.size(); i++) {
			Integer keyNumber = keyNumbers.get(i);
			if(keyNumber == 14) {
				continue;
			}
			String access = compactPermissionMap.get(keyNumber);
			StringBuffer buffer = new StringBuffer();
			if(access.contains("R")) {
				buffer.append(getString(R.string.fileAccessKeyRead));
			}
			if(access.contains("W")) {
				if(buffer.length() > 0) {
					buffer.append(", ");
				}
				buffer.append(getString(R.string.fileAccessKeyWrite));
			}
			if(access.contains("C")) {
				if(buffer.length() > 0) {
					buffer.append(", ");
				}
				buffer.append(getString(R.string.fileAccessKeyChange));
			}
				
			keys.add(getString(R.string.fileAccessKey, keyNumber, buffer.toString()));
		}
		
		String names[] = keys.toArray(new String[keys.size()]);
		
	    AlertDialog.Builder alertDialog = new AlertDialog.Builder(MainActivity.this);
	    LayoutInflater inflater = getLayoutInflater();
	    View convertView = (View) inflater.inflate(R.layout.dialog_list, null);
	    alertDialog.setView(convertView);

	    alertDialog.setTitle(getString(R.string.fileAccessSelectKey));
	    ListView lv = (ListView) convertView.findViewById(R.id.listView);
	    ArrayAdapter<String> adapter = new ArrayAdapter<String>(MainActivity.this, android.R.layout.simple_list_item_1, names);
	    lv.setAdapter(adapter);
	    final AlertDialog show = alertDialog.show();
	    
	    lv.setOnItemClickListener(new OnItemClickListener() {

			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
				show.dismiss();

				Integer keyNumber = keyNumbers.get(position);
				
				listener.onKeyNumber(keyNumber, compactPermissionMap.get(keyNumber));
			}
		});
	}
	
	private void showKeySelector(DesfireKeyType type, final OnKeyListener listener) {
		MainApplication application = MainApplication.getInstance();
		
		DataSource dataSource = application.getDataSource();
		
		final List<DesfireKey> keys;
		if(type == DesfireKeyType.TDES || type == DesfireKeyType.DES) {
			keys = new ArrayList<>();
			
			keys.addAll(dataSource.getKeys(DesfireKeyType.DES));
			keys.addAll(dataSource.getKeys(DesfireKeyType.TKTDES));
		} else {
			keys = dataSource.getKeys(type);
		}
		
		if(!keys.isEmpty()) {
			String names[] = new String[keys.size()];
			for(int i = 0; i < names.length; i++) {
				names[i] = getString(R.string.applicationAuthenticateKeyNameVersion, keys.get(i).getName(), keys.get(i).getVersionAsHexString());
			}
		    AlertDialog.Builder alertDialog = new AlertDialog.Builder(MainActivity.this);
		    LayoutInflater inflater = getLayoutInflater();
		    View convertView = (View) inflater.inflate(R.layout.dialog_list, null);
		    alertDialog.setView(convertView);

		    alertDialog.setTitle(getString(R.string.applicationAuthenticateKey, getName(type)));
		    ListView lv = (ListView) convertView.findViewById(R.id.listView);
		    ArrayAdapter<String> adapter = new ArrayAdapter<String>(MainActivity.this, android.R.layout.simple_list_item_1, names);
		    lv.setAdapter(adapter);
		    final AlertDialog show = alertDialog.show();
		    
		    lv.setOnItemClickListener(new OnItemClickListener() {

				@Override
				public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
					show.dismiss();

					DesfireKey key = keys.get(position);

					listener.onKey(key);
				}

			});
		} else {
			Log.d(TAG, "No " + type + " keys found");
		}
	}

	public void showToast(int resource, Object ... args) {
		Toast.makeText(getApplicationContext(), getString(resource, args), Toast.LENGTH_LONG).show();
	}

	public void showToast(int resource) {
		Toast.makeText(getApplicationContext(), getString(resource), Toast.LENGTH_LONG).show();
	}

	public void showShortToast(int resource) {
		Toast.makeText(getApplicationContext(), getString(resource), Toast.LENGTH_SHORT).show();
	}

	private void showFileFragment(DesfireFile file) {
		Log.d(TAG, "showFileFragment");
		
		// Create new fragment and transaction
		final FileFragment newFragment = new FileFragment();
		newFragment.setFile(file);
		
		newFragment.setOnItemClickListener(new OnItemClickListener(){

			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
				Log.d(TAG, "onItemClick "  + position + " for " + id);
				
				ApplicationDetail applicationDetail = newFragment.getApplicationDetail(position);
				
				if(applicationDetail instanceof ApplicationDetailRecord) {
					ApplicationDetailRecord key = (ApplicationDetailRecord)applicationDetail;
					
					byte[] content = key.getContent();
					
					Log.d(TAG, "Save " + Utils.getHexString(content));
				}
				
			}
			
		});
		FragmentTransaction transaction = getFragmentManager().beginTransaction();

		// Replace whatever is in the fragment_container view with this fragment,
		// and add the transaction to the back stack
		transaction.replace(R.id.content, newFragment, "file");
		transaction.addToBackStack("file");

		// Commit the transaction
		transaction.commit();		
	}
	
	@Override
	public void onConfigurationChanged(Configuration newConfig) {
		super.onConfigurationChanged(newConfig);
	}

	@Override
	public void onBackStackChanged() {
		invalidateOptionsMenu();
	}
	
	private class FileCallbacks implements FileSaveFragment.Callbacks {

		@Override
		public boolean onCanSave(String absolutePath, String fileName) {
			return absolutePath != null && absolutePath.length() > 0 && fileName != null && fileName.length() > 0;
		}
	
		@Override
		public void onConfirmSave(String absolutePath, String fileName) {
			if(absolutePath == null || absolutePath.length() == 0 || fileName == null || fileName.length() == 0) {
		    	getFragmentManager().popBackStack();
	
				
				return;
			}
	
			
			FileFragment fragment = (FileFragment) getFragmentManager().findFragmentByTag("file");
			
			DesfireFile file = fragment.getFile();
			
			if(file instanceof ValueDesfireFile) {
				throw new IllegalArgumentException();
			}

			byte[] data;
			if(file instanceof StandardDesfireFile) {
				StandardDesfireFile standardDesfireFile = (StandardDesfireFile)file;
				data = standardDesfireFile.getData();
			} else if(file instanceof RecordDesfireFile) {
				RecordDesfireFile recordDesfireFile = (RecordDesfireFile)file;
				data = recordDesfireFile.getRecords();
			} else {
				throw new IllegalArgumentException();
			}
			
		
			FileOutputStream out = null;
			try {
				File outputFile = new File(absolutePath, fileName);
				
				if(outputFile.exists()) {
					if(!outputFile.delete()) {
						Log.d(TAG, "Unable to delete file " + outputFile);
						
						return;
					}
				}
				
				out = new FileOutputStream(outputFile);
				out.write(data);

				out.flush();
				
	        	Log.d(TAG, "Saved file " + file);
	        	
	    		Toast.makeText(getApplicationContext(), getString(R.string.fileSavedSuccess, outputFile.toString()), Toast.LENGTH_LONG).show();
	        } catch (IOException e) {
	        	Log.d(TAG, "Problem saving file " + absolutePath + " " + fileName);
	        	
	    		Toast.makeText(getApplicationContext(), getString(R.string.fileSavedFailure), Toast.LENGTH_LONG).show();
	        	
	        } finally {
	        	if(out != null) {
	        		try {
	        			out.close();
	        		} catch(IOException e) {
	        			// ignore
	        		}
	        	}
	        }
	    	getFragmentManager().popBackStack();

			
			
			
		}
	}

	
	public void show(AlertDialog altertDialog) {
		synchronized(this) {
			if(alertDialog != null) {
				alertDialog.cancel();
			}
			// create alert dialog
			this.alertDialog = altertDialog;
			
			runOnUiThread(new Runnable() {
				public void run() {
					// show it
					alertDialog.show();
			}});
			
		}
	}
	
	public void hideDialog() {
		synchronized(this) {
			if(alertDialog != null) {
				alertDialog.cancel();
				alertDialog = null;
			}
		}
	}

	private void readFile(final DesfireFile desfireFile) {
		
		Log.d(TAG, "Read file access");
		if(desfireFile instanceof StandardDesfireFile) {
			try {
				StandardDesfireFile standardDesfireFile = (StandardDesfireFile)desfireFile;

				if(!standardDesfireFile.isData()) {
					Log.d(TAG, "Read data from file " + Integer.toHexString(desfireFile.getId()));
					
					byte[] data = mifare_desfire_read_data (tag, (byte)desfireFile.getId(), 0, 0);
				
					Log.d(TAG, "Read data length " + data.length);
				
					standardDesfireFile.setData(data);
				}
			} catch (Exception e) {
				Log.d(TAG, "Problem reading file", e);
			}
		} else if(desfireFile instanceof ValueDesfireFile) {
			try {
				ValueDesfireFile valueDesfireFile = (ValueDesfireFile)desfireFile;

				if(!valueDesfireFile.isValue()) {
					Log.d(TAG, "Read value from file " + Integer.toHexString(desfireFile.getId()));
					
					Integer value = mifare_desfire_get_value(tag, (byte)desfireFile.getId());

					Log.d(TAG, "Read value " + value);
				
					valueDesfireFile.setValue(value);
				}
			} catch (Exception e) {
				Log.d(TAG, "Problem reading file", e);
			}
		} else if(desfireFile instanceof RecordDesfireFile) {
			try {
				RecordDesfireFile recordDesfireFile = (RecordDesfireFile)desfireFile;

				if(!recordDesfireFile.isRecords()) {
					Log.d(TAG, "Read records from file " + Integer.toHexString(desfireFile.getId()));
					
					byte[] records = mifare_desfire_read_records (tag, (byte)desfireFile.getId(), 0, recordDesfireFile.getCurrentRecords());

					Log.d(TAG, "Read " + recordDesfireFile.getCurrentRecords() + " records " + Utils.getHexString(records));
					
					recordDesfireFile.setRecords(records);
				}
			} catch (Exception e) {
				Log.d(TAG, "Problem reading record file", e);
			}
		}
	}

	@Override
	public boolean onCanSave(String absolutePath, String fileName) {
		return callbacks.onCanSave(absolutePath, fileName);
	}

	@Override
	public void onConfirmSave(String absolutePath, String fileName) {
		callbacks.onConfirmSave(absolutePath, fileName);
		
		this.callbacks = null;
	}

	private boolean isConnected() {
		MifareTag tag = this.tag;

		if(tag != null) {
			try {
				DefaultIsoDepWrapper wrapper = (DefaultIsoDepWrapper) tag.getIo().getIsoDepWrapper();

				return wrapper.getIsoDep().isConnected();
			} catch (Exception e) {
				// Tag went out of date / was reset (common on MIUI): treat as disconnected
				// instead of letting SecurityException crash the TagPresenceScanner.
				Log.d(TAG, "Tag is out of date or disconnected", e);
				return false;
			}
		}
		return false;
	}

	/**
	 * 
	 * Launch an activity for NFC (or wireless) settings, so that the user might enable or disable nfc
	 * 
	 */

	
	protected void startNfcSettingsActivity() {
		if (android.os.Build.VERSION.SDK_INT >= 16) {
			startActivity(new Intent(ACTION_NFC_SETTINGS)); // android.provider.Settings.ACTION_NFC_SETTINGS
		} else {
			startActivity(new Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS));
		}
	}
	
    protected static class TagPresenceScanner extends Handler {
    	
        private static final long TAG_RESCAN_INTERVAL_MS = 1000;

		private WeakReference<MainActivity> activityReference;
		
		public TagPresenceScanner(MainActivity activity) {
			this.activityReference = new WeakReference<MainActivity>(activity);
		}

        void resume() {
        	synchronized (this) {
	            if (!hasMessages(0)) {
	                sendEmptyMessage(0);
	            }
        	}
        }
        
        public void resumeDelayed() {
        	synchronized (this) {
	            if (!hasMessages(0)) {
	            	 sendEmptyMessageDelayed(0, TAG_RESCAN_INTERVAL_MS);
	            }
        	}
        }

        public void pause() {
        	synchronized (this) {
        		removeMessages(0);
        	}
        }

        @Override
        public void handleMessage(android.os.Message msg) {
        	//Log.v(TAG, "Handle message");
        	
        	MainActivity activity = activityReference.get();
			if(activity != null) {
				if(activity.isConnected()) {
					resumeDelayed();
				} else {
					activity.onTagLost();
					
					pause();
				}
			}
        }
    }
}

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package GUI;

import java.io.File;
import javax.swing.filechooser.FileFilter;

/**
 *
 * @author Michal
 */
class SimpleFileFilter extends FileFilter {

    String[] extensions;
    String description;

    public SimpleFileFilter(String ext) {
        this(new String[]{ext}, null);
    }

    public SimpleFileFilter(String[] exts, String descr) {
// clone and lowercase the extensions
        extensions = new String[exts.length];
        for (int i = exts.length - 1; i >= 0; i--) {
            extensions[i] = exts[i].toLowerCase();
        }
// make sure we have a valid (if simplistic) description
        description = (descr == null ? exts[0] + " files" : descr);
    }

    public boolean accept(File f) {
        //  dovoluje pracovat 
        if (f.isDirectory()) {
            return true;
        }
        // v poriadku, je to spravny subor, skontroluje koncovku
        String name = f.getName().toLowerCase();
        for (int i = extensions.length - 1; i >= 0; i--) {
            if (name.endsWith(extensions[i])) {
                return true;
            }
        }
        return false;
    }
    //vrati popis 
    public String getDescription() {
        return description;
    }
}



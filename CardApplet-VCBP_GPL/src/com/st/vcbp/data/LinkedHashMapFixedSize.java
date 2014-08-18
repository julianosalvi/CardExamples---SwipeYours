/**
 * This file is part of CardApplet-VCBP which is card applet implementation 
 * of V Cloud-Based Payments for SimplyTapp cloud platform.
 * Copyright 2014 SimplyTapp, Inc.
 * 
 * CardApplet-VCBP is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 * 
 * CardApplet-VCBP is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License 
 * along with CardApplet-VCBP.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.st.vcbp.data;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public class LinkedHashMapFixedSize<K, V> extends LinkedHashMap<K, V> {

    private static final long serialVersionUID = 1L;

    private int fixedSize;

    public LinkedHashMapFixedSize(int initialCapacity) {
        super(initialCapacity);

        this.fixedSize = initialCapacity;
    }

    public void updateSize(int newSize) {
        if (newSize < this.size()) {
            // Remove oldest entries to reduce size.
            Iterator<Map.Entry<K, V>> iterator = this.entrySet().iterator();
            while ((newSize < this.size()) && iterator.hasNext()) {
                iterator.next();
                iterator.remove();
            }
        }

        this.fixedSize = newSize;
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        return size() > this.fixedSize;
    }

}

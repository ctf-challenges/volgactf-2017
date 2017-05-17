#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import volgawaves
import shutil
from math import log2, ceil
import numpy as np
from skimage.io import imread
from argparse import ArgumentParser


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('input', metavar='<INPUT>', type=str, help='input image')
    parser.add_argument('output', metavar='<OUTPUT>', type=str, help='output file')
    parser.add_argument('-qf', metavar='<QF>', type=float, default=0.05, help='QF')
    args = parser.parse_args()

    # read and pad input image
    image = imread(args.input, as_grey=True)
    rows, cols = image.shape
    n = 2**int(max(ceil(log2(rows)), ceil(log2(cols))))
    image_padded = np.zeros((n, n), dtype=np.float64)
    image_padded[0:rows, 0:cols] = image

    # process the image
    cl = np.array([0.4829629131445341, 0.8365163037378077, 0.2241438680420134, -0.12940952255126034], dtype=np.float64)
    fs = volgawaves.dp(image_padded, cl)
    fs[abs(fs) < args.qf] = 0.0

    # save result to the output file
    np.savez_compressed(args.output, fs=fs.astype(np.float32))
    shutil.move(args.output+'.npz', args.output)

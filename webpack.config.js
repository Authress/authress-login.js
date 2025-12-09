import webpack from 'webpack';
import CompressionPlugin from 'compression-webpack-plugin';
import TerserPlugin from 'terser-webpack-plugin';
import fs from 'fs-extra';
import { fileURLToPath } from 'url';
import path from 'path';

const underscoreDirname = path.dirname(fileURLToPath(import.meta.url));
const packageMetadataFile = path.join(underscoreDirname, 'package.json');
const packageMetadata = await fs.readJson(packageMetadataFile);

const webpackBabelConfigFile = path.join(underscoreDirname, 'webpack.babelrc.json');
const webpackBabelConfig = await fs.readJson(webpackBabelConfigFile);

const version = packageMetadata.version.replace(/"/g, '');

const commonPlugins = [
  new webpack.ProvidePlugin({ Buffer: ['buffer', 'Buffer'] }),
  new webpack.HotModuleReplacementPlugin(),
  new webpack.optimize.LimitChunkCountPlugin({ maxChunks: 1 }),
  new CompressionPlugin()
];

if (process.env.NODE_ENV === 'production') {
  const banner = `
/**
* @preserve
* Authress Login SDK ${version.replace()}
* License: Apache-2.0
* Repo   : https://github.com/Authress/login-sdk.js
* Author : Authress Developers
*/`;
  commonPlugins.push(new webpack.BannerPlugin({
    raw: true, banner
  }));
}

export default {
  mode: 'production',
  entry: './src/index.js',
  devtool: process.env.NODE_ENV ? undefined : 'cheap-module-source-map',
  output: {
    path: path.join(__dirname, 'dist'),
    filename: 'authress.min.js',
    publicPath: '',
    library: {
      name: 'authress',
      type: 'umd'
    },
    globalObject: 'this'
  },
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        extractComments: {
          condition: /^\**!|@preserve|@license|@cc_on/i,
          banner: () => `Authress Login SDK ${version} | Author - Authress Developers | License information can be found at https://github.com/Authress/login-sdk.js`
        }
      })
    ]
  },
  devServer: {
    port: 8080,
    hot: true
  },
  module: {
    rules: [
      {
        enforce: 'pre',
        test: /\.js$/,
        exclude: /node_modules/,
        loader: 'eslint-loader',
        options: {
          emitWarning: true,
          // failOnWarning: true,
          // failOnError: true,
          fix: false,
          configFile: './.eslintrc',
          outputReport: {
            filePath: './eslint_report.html',
            formatter: 'html'
          }
        }
      },
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: [
          {
            loader: 'babel-loader',
            // eslint-disable-next-line global-require
            options: webpackBabelConfig
          }
        ]
      },
      {
        test: /\.css$/,
        use: [
          { loader: 'style-loader' }, // creates style nodes in HTML from CommonJS strings
          { loader: 'css-loader' } // translates CSS into CommonJS
        ]
      },
      {
        test: /\.(woff|woff2|eot|ttf|otf)$/,
        use: [{
          loader: 'file-loader',
          options: {
            name: '[name].[ext]'
          }
        }]
      }
    ]
  },
  resolve: {
    fallback: {
      // path: require.resolve('path-browserify')
    },
    alias: {
      '~': path.resolve(__dirname, 'src')
    }
  },
  plugins: commonPlugins
};

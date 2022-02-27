const webpack = require('webpack');
const CompressionPlugin = require('compression-webpack-plugin');
const TerserPlugin = require('terser-webpack-plugin');

const path = require('path');

const version = JSON.stringify(require('./package.json').version).replace(/"/g, '');

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
*`;
  commonPlugins.push(new webpack.BannerPlugin({
    raw: true, banner
  }));
}

module.exports = {
  mode: 'production',
  entry: './src/index.js',
  devtool: 'cheap-module-source-map',
  output: {
    path: path.join(__dirname, 'dist'),
    filename: 'authress.min.js',
    publicPath: ''
  },
  optimization: {
    minimizer: [
      new TerserPlugin({
        extractComments: {
          condition: /^\**!|@preserve|@license|@cc_on/i,
          banner: licenseFile => `Authress Login SDK ${version} | Author - Authress Developers | License information can be found in ${licenseFile} `
        }
      })
    ]
  },
  devServer: {
    contentBase: path.join(__dirname, 'docs'),
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
            options: require('./webpack.babelrc.json')
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
      path: require.resolve('path-browserify')
    },
    alias: {
      '~': path.resolve(__dirname, 'src')
    }
  },
  plugins: commonPlugins
};

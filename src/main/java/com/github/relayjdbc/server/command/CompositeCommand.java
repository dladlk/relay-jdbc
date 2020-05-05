package com.github.relayjdbc.server.command;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.sql.SQLException;
import java.util.Arrays;

import com.github.relayjdbc.command.AbstractCommand;
import com.github.relayjdbc.command.Command;
import com.github.relayjdbc.command.ConnectionContext;
import com.github.relayjdbc.serial.UIDEx;
/**
 * CompositeCommand is used to transport several commands in a single HTTP request.
 * Commands are added via method {@link #add(UIDEx, Command)} which return
 * fake UIDEx instance, which must be updated by method {@link #updateResultUIDEx(Object[])} 
 * after command execution.
 * @author semenov
 *
 */
public class CompositeCommand extends AbstractCommand implements Externalizable {
	private static final int INCREMENT = 5;
	
	private Command[] _commands = new Command[INCREMENT];
	private UIDEx[] _uidexs = new UIDEx[INCREMENT];
	private transient UIDEx[] _futureResults;
	private int _size = 0;
	
	
	public CompositeCommand() {
		this._futureResults = new UIDEx[INCREMENT];
	}

	CompositeCommand(Command[] commands, UIDEx[] uidexs) {
		this._commands = commands;
		this._uidexs = uidexs;
		this._size = commands.length;
	}

	/**
	 * adds given command to this command packet to be executed 
	 * on target identified by reg. Returns fake {@link UIDEx} instance, 
	 * which could be used for other commands in this {@link CompositeCommand} instance.
	 * On server side the fake {@link UIDEx} instance is replaced by real one,
	 * after command is executed for all subsequent commands.
	 * @param reg the target identifier
	 * @param command the command to execute
	 * @return fake {@link UIDEx} instance, which could be used for other commands in this {@link CompositeCommand} instance.
	 * @throws IllegalArgumentException if reg references invalid object.
	 */
	public synchronized UIDEx add(UIDEx reg, Command command){
		// check UIDEx is valid
		long x = reg.getUID().longValue();
		if (x<0L && x<=-(_size+1)){
			throw new IllegalArgumentException("Invalid reg: "+reg);
		}		
		
		if (_size>=_commands.length){
			Command[] c = new Command[_commands.length+INCREMENT];
			System.arraycopy(_commands, 0, c, 0, _commands.length);
			_commands = c;
			UIDEx[] u = new UIDEx[_uidexs.length+INCREMENT];
			System.arraycopy(_uidexs, 0, u, 0, _uidexs.length);
			_uidexs = u;
			UIDEx[] r = new UIDEx[_uidexs.length+INCREMENT];
			System.arraycopy(_futureResults, 0, r, 0, _futureResults.length);
			_futureResults = r;
		}

		_uidexs[_size] = reg;
		_commands[_size] = command;		
		return _futureResults[_size] = new UIDEx(Long.valueOf(-(++_size)), Integer.MIN_VALUE, Integer.MAX_VALUE); 
	}
	
	public synchronized int size(){
		return _size;
	}
	
	@Override
	public synchronized void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(_size);
		for (int i=0; i<_size; i++){
			out.writeObject(_uidexs[i]);
			out.writeObject(_commands[i]);
		}
	}

	@Override
	public synchronized void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		int _size = in.readInt();
		_commands = new Command[_size];
		_uidexs = new UIDEx[_size];
		for (int i=0; i<_size; i++){
			_uidexs[i] = (UIDEx) in.readObject();
			_commands[i] = (Command) in.readObject();
		}
	}

	@Override
	public synchronized Object execute(Object target, ConnectionContext ctx) throws SQLException {
		Object [] result = new Object[_size];
		for (int i=0; i<_size; i++){
			Long uid = null;
			if (_uidexs[i]!=null){
				uid = _uidexs[i].getUID();
				long u = uid.longValue();
				if (u<0L){
					// negative uid value means that uid should be taken from result of previously executed command
					// the result of that command should be UIDEx
					if ((u = -u - 1L)>=0L && u<i && result[(int)u] instanceof UIDEx ){
						uid = ((UIDEx) result[(int)u]).getUID();
					} else {
						throw new SQLException("Invalid target UIDEx: "+_uidexs[i]);
					}
				}
			}
			result[i] = ctx.executeCommand(uid, _commands[i], null);
		}
		return result;
	}
	/**
	 * update fake {@link UIDEx} instances returned by {@link #add(UIDEx, Command)}
	 * converting them to real ones on client side. 
	 * @param results the result Objects to update
	 */
	public synchronized void updateResultUIDEx(Object [] results) {
		assert results!=null : CompositeCommand.class + " nevere returns null result";
		if (_futureResults!=null){
			for (int i=0; i<_size && i<results.length; i++){
				if (results[i] instanceof UIDEx){
					_futureResults[i].copyFrom((UIDEx) results[i]);
				}
			}
		}
	}

	public synchronized Command[] getCommands() {
		return _commands;
	}

	synchronized UIDEx[] getUIDExs() {
		return _uidexs;
	}
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(this.getClass().getSimpleName());
		sb.append(" ");
		sb.append(this._size);
		sb.append(" commands: ");
		sb.append(Arrays.toString(this._commands));
		return sb.toString();
	}
}
